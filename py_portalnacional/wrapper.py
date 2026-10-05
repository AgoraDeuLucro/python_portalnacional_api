"""
Wrapper não oficial das APIs do Portal Nacional de NFS-e
(Sistema Nacional da Nota Fiscal de Serviço Eletrônica).

Autenticação: mTLS com certificado digital ICP-Brasil (A1 PFX/P12 ou PEM).
"""

import base64
import gzip
import json
import os
import tempfile
import threading
from time import sleep, time

import requests
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)

# ---------------------------------------------------------------------------
# Constantes de rejeição (distribuição por NSU)
# ---------------------------------------------------------------------------
REJEICOES_NSU_VAZIO = {"E2305", "E2020", "E2215", "E2230"}
REJEICAO_CHAVE_NAO_ENCONTRADA = "E2240"
REJEICAO_CHAVE_SEM_VINCULO = "E2241"

# Códigos de evento NFS-e (referência)
# Cancelamento Direto pelo Emitente: 101101
# Cancelamento por Substituição: 105102
# Solicitação de Análise Fiscal para Cancelamento: 101103
# Cancelamento Deferido por Análise Fiscal: 105104
# Confirmação do Prestador: 202201
# Confirmação do Tomador: 203202
# Rejeição do Tomador: 203206
# Cancelamento por Ofício (Fisco): 305101
# Bloqueio por Ofício (Fisco): 305102

_URLS = {
    "producao": {
        "sefin": "https://sefin.nfse.gov.br/SefinNacional",
        "adn": "https://adn.nfse.gov.br/contribuintes",
        "danfse": "https://adn.nfse.gov.br/danfse",
        "cnc": "https://adn.nfse.gov.br/cnc",
        "parametrizacao": "https://adn.nfse.gov.br/parametrizacao",
    },
    "homologacao": {
        "sefin": "https://sefin.producaorestrita.nfse.gov.br/API/SefinNacional",
        "adn": "https://adn.producaorestrita.nfse.gov.br/contribuintes",
        "danfse": "https://adn.producaorestrita.nfse.gov.br/danfse",
        "cnc": "https://adn.producaorestrita.nfse.gov.br/cnc",
        "parametrizacao": "https://adn.producaorestrita.nfse.gov.br/parametrizacao",
    },
}

_NSU_COOLDOWN_SECONDS = 3600  # 1 hora
_LOTE_POLLING_SECONDS = 5


class auth:
    """Classe base: mTLS com certificado ICP-Brasil e request centralizado."""

    def __init__(
        self,
        cert_path="",
        cert_password="",
        cert_pem="",
        key_pem="",
        environment="homologacao",
        print_error=True,
    ):
        """
        Args:
            cert_path (str): Caminho para certificado A1 (.pfx / .p12).
            cert_password (str): Senha do arquivo PFX/P12.
            cert_pem (str): Caminho para certificado já em PEM (alternativa ao PFX).
            key_pem (str): Caminho para chave privada já em PEM (alternativa ao PFX).
            environment (str): ``"producao"`` ou ``"homologacao"`` (produção restrita).
            print_error (bool): Se True, imprime detalhes de erros HTTP.
        """
        if environment not in _URLS:
            raise ValueError(
                f'environment deve ser "producao" ou "homologacao", recebido: {environment!r}'
            )

        self.print_error = print_error
        self.environment = environment
        urls = _URLS[environment]
        self.base_url_sefin = urls["sefin"]
        self.base_url_adn = urls["adn"]
        self.base_url_danfse = urls["danfse"]
        self.base_url_cnc = urls["cnc"]
        self.base_url_parametrizacao = urls["parametrizacao"]

        self._temp_files = []
        self._nsu_blocked_until = 0.0
        self._last_lote_poll = 0.0
        self._rl_lock = threading.Lock()

        self.session = requests.Session()
        self.session.verify = True
        self._setup_certificate(cert_path, cert_password, cert_pem, key_pem)

    def _setup_certificate(self, cert_path, cert_password, cert_pem, key_pem):
        if cert_pem and key_pem:
            if not os.path.isfile(cert_pem):
                raise FileNotFoundError(f"Certificado PEM não encontrado: {cert_pem}")
            if not os.path.isfile(key_pem):
                raise FileNotFoundError(f"Chave PEM não encontrada: {key_pem}")
            self.session.cert = (cert_pem, key_pem)
            return

        if cert_path:
            if not os.path.isfile(cert_path):
                raise FileNotFoundError(f"Certificado PFX/P12 não encontrado: {cert_path}")
            pem_cert, pem_key = self._pfx_to_pem(cert_path, cert_password)
            self.session.cert = (pem_cert, pem_key)
            return

        # Permite instanciar sem certificado (útil para testes unitários de montagem de URL)
        self.session.cert = None

    def _pfx_to_pem(self, cert_path, cert_password):
        """Converte PFX/P12 em arquivos PEM temporários (cert + key)."""
        with open(cert_path, "rb") as f:
            pfx_data = f.read()

        password = cert_password.encode() if cert_password else None
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            pfx_data, password
        )

        if private_key is None or certificate is None:
            raise ValueError(
                "Não foi possível extrair chave/certificado do PFX. "
                "Verifique a senha e se o arquivo contém um certificado de cliente."
            )

        cert_fd, cert_tmp = tempfile.mkstemp(suffix=".pem")
        key_fd, key_tmp = tempfile.mkstemp(suffix=".pem")
        self._temp_files.extend([cert_tmp, key_tmp])

        try:
            with os.fdopen(cert_fd, "wb") as cf:
                cf.write(certificate.public_bytes(Encoding.PEM))
                if additional_certs:
                    for extra in additional_certs:
                        cf.write(extra.public_bytes(Encoding.PEM))

            with os.fdopen(key_fd, "wb") as kf:
                kf.write(
                    private_key.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.TraditionalOpenSSL,
                        NoEncryption(),
                    )
                )
        except Exception:
            self._cleanup_temp_files()
            raise

        return cert_tmp, key_tmp

    def _cleanup_temp_files(self):
        for path in self._temp_files:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass
        self._temp_files.clear()

    def __del__(self):
        try:
            self._cleanup_temp_files()
            if hasattr(self, "session"):
                self.session.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Rate limiting específico NFS-e
    # ------------------------------------------------------------------

    def _nsu_check_cooldown(self):
        """Bloqueia se ainda estiver no cooldown de 1h após NSU vazio."""
        with self._rl_lock:
            now = time()
            if now < self._nsu_blocked_until:
                remaining = int(self._nsu_blocked_until - now)
                raise Exception(
                    f"Consulta NSU bloqueada por cooldown de 1 hora após "
                    f"'nenhum documento localizado'. Aguarde {remaining}s "
                    f"(desbloqueio em ~{remaining // 60} min)."
                )

    def _nsu_apply_cooldown(self):
        """Aplica cooldown de 1 hora após rejeição de NSU vazio."""
        with self._rl_lock:
            self._nsu_blocked_until = time() + _NSU_COOLDOWN_SECONDS

    def _wait_polling_interval(self, seconds=_LOTE_POLLING_SECONDS):
        """Garante intervalo mínimo entre consultas de recibo de lote."""
        with self._rl_lock:
            now = time()
            elapsed = now - self._last_lote_poll
            if self._last_lote_poll > 0 and elapsed < seconds:
                sleep(seconds - elapsed)
            self._last_lote_poll = time()

    # ------------------------------------------------------------------
    # Request centralizado
    # ------------------------------------------------------------------

    def _extract_rejection_codes(self, body):
        """Extrai códigos de rejeição (E####) do corpo da resposta."""
        codes = set()
        if body is None:
            return codes
        text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
        for code in REJEICOES_NSU_VAZIO | {REJEICAO_CHAVE_NAO_ENCONTRADA, REJEICAO_CHAVE_SEM_VINCULO}:
            if code in text:
                codes.add(code)
        # Busca genérica E#### em estruturas aninhadas
        if isinstance(body, dict):
            for key in ("codigo", "code", "cStat", "erro", "erros"):
                val = body.get(key)
                if isinstance(val, str) and val.startswith("E"):
                    codes.add(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            c = item.get("codigo") or item.get("code") or ""
                            if isinstance(c, str) and c.startswith("E"):
                                codes.add(c)
                        elif isinstance(item, str) and item.startswith("E"):
                            codes.add(item)
        return codes

    def _parse_response_body(self, response):
        content_type = (response.headers.get("Content-Type") or "").lower()
        text = response.text or ""
        if not text:
            return None
        if "application/json" in content_type or text.lstrip().startswith(("{", "[")):
            try:
                return response.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                return text
        return text

    def request(self, method="GET", url="", headers=None, params=None, data=None, json_data=None):
        """
        Executa requisição HTTP via sessão mTLS.

        Returns:
            requests.Response | None: Resposta em sucesso (2xx) ou None em erro
            tratado (403/404). Em 502/503 retorna a Response para o caller decidir.
        """
        req_params = params if params is not None else {}
        req_headers = dict(headers) if headers else {}
        if "Accept" not in req_headers:
            req_headers["Accept"] = "application/json"

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=req_params,
                headers=req_headers,
                data=data,
                json=json_data,
                timeout=60,
            )
        except requests.exceptions.SSLError as e:
            if self.print_error:
                print(f"Erro SSL/mTLS na requisição: {e}")
            raise
        except requests.exceptions.RequestException as e:
            if self.print_error:
                print(f"Erro na requisição: {e}")
            raise

        if response.status_code in (200, 201, 204):
            return response

        if response.status_code in (502, 503):
            if self.print_error:
                print(
                    f"Serviço indisponível (HTTP {response.status_code}) em {url}. "
                    "A rota /danfse é notoriamente instável (NT 008/2026)."
                )
            return response

        body = self._parse_response_body(response)
        if self.print_error:
            print(
                f"""Erro no retorno da API do Portal Nacional NFS-e
Status: {response.status_code}
URL: {url}
Metodo: {method}
Parametros: {req_params}
Resposta: {body}"""
            )

        if response.status_code in (403, 404):
            return None

        return response


# ---------------------------------------------------------------------------
# Módulos
# ---------------------------------------------------------------------------


class nfse(auth):
    """Emissão e consulta de NFS-e (Sefin Nacional)."""

    def emitir(self, xml_dps):
        """
        Geração síncrona de NFS-e a partir do XML da DPS.

        POST /nfse

        Se a DPS referenciar chave de acesso de NFS-e a substituir, a API
        cancela a nota anterior (evento de substituição) e autoriza a nova.

        Args:
            xml_dps (str): XML da DPS (UTF-8), já assinado digitalmente.

        Returns:
            dict | str: Corpo da resposta (JSON ou XML) ou {} em falha.
        """
        url = self.base_url_sefin + "/nfse"
        response = self.request(
            "POST",
            url=url,
            json_data={"xml": xml_dps},
            headers={"Content-Type": "application/json"},
        )
        if response is None:
            return {}
        if response.status_code not in (200, 201):
            return {"status_code": response.status_code, "body": self._parse_response_body(response)}
        return self._parse_response_body(response) or {}

    def consultar(self, chave_acesso):
        """
        Consulta NFS-e pela chave de acesso (50 caracteres).

        GET /nfse/{chaveAcesso}

        O XML completo só é retornado se o CNPJ/CPF do certificado for
        Prestador, Tomador ou Intermediário da nota.

        Args:
            chave_acesso (str): Chave de acesso da NFS-e.

        Returns:
            dict | str: Conteúdo da NFS-e ou {} em falha.
        """
        url = self.base_url_sefin + f"/nfse/{chave_acesso}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def emitir_decisao_judicial(self, xml_nfse):
        """
        Emissão por decisão administrativa/judicial (bypass de validações).

        POST /decisao-judicial/nfse

        Exige XML da NFS-e completa (não apenas DPS) com cStat=102.
        A responsabilidade pelos cálculos recai sobre o contribuinte.

        Args:
            xml_nfse (str): XML completo da NFS-e.

        Returns:
            dict | str: Corpo da resposta ou {} em falha.
        """
        url = self.base_url_sefin + "/decisao-judicial/nfse"
        response = self.request(
            "POST",
            url=url,
            json_data={"xml": xml_nfse},
            headers={"Content-Type": "application/json"},
        )
        if response is None:
            return {}
        if response.status_code not in (200, 201):
            return {"status_code": response.status_code, "body": self._parse_response_body(response)}
        return self._parse_response_body(response) or {}

    def emitir_lote_assincrono(self, xmls):
        """
        Envio assíncrono de lote de DPS (máx. 50 XMLs).

        POST /NotaNacional/EnviarAssincrono

        Compacta a lista com GZip e codifica em Base64 no envelope JSON.

        Args:
            xmls (list[str]): Lista de XMLs de DPS (máx. 50).

        Returns:
            dict: Resposta com número de recibo, ou {} em falha.
        """
        if not xmls:
            raise ValueError("xmls não pode ser vazio")
        if len(xmls) > 50:
            raise ValueError("Lote assíncrono aceita no máximo 50 XMLs")

        compressed = gzip.compress(json.dumps({"xmlList": xmls}).encode("utf-8"))
        payload = {"lote": base64.b64encode(compressed).decode("ascii")}

        url = self.base_url_sefin + "/NotaNacional/EnviarAssincrono"
        response = self.request(
            "POST",
            url=url,
            json_data=payload,
            headers={"Content-Type": "application/json"},
        )
        if response is None:
            return {}
        if response.status_code not in (200, 201):
            return {"status_code": response.status_code, "body": self._parse_response_body(response)}
        return self._parse_response_body(response) or {}

    def consultar_lote(self, recibo):
        """
        Consulta o status de processamento de um lote assíncrono.

        Respeita intervalo mínimo de 5 segundos entre consultas.

        Args:
            recibo (str): Número do recibo retornado por ``emitir_lote_assincrono``.

        Returns:
            dict | str: Status do lote ou {} em falha.
        """
        self._wait_polling_interval(_LOTE_POLLING_SECONDS)
        # Endpoint de consulta de protocolo/recibo (padrão Sefin)
        url = self.base_url_sefin + f"/NotaNacional/ConsultarLote/{recibo}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            if response is not None:
                return {"status_code": response.status_code, "body": self._parse_response_body(response)}
            return {}
        return self._parse_response_body(response) or {}


class dps(auth):
    """Consulta de Declaração de Prestação de Serviços (Sefin Nacional)."""

    def consultar_chave(self, id_dps):
        """
        Recupera a chave de acesso da NFS-e a partir do identificador da DPS.

        GET /dps/{id}

        ID da DPS: 45 posições =
        IBGE(7) + TipoInscrição(1) + CPF/CNPJ(14) + SérieDPS(5) + NúmDPS(15).

        Sigilo fiscal: só retorna a chave se o certificado for de um dos atores
        (Prestador, Tomador ou Intermediário).

        Args:
            id_dps (str): Identificador da DPS (45 caracteres).

        Returns:
            dict | str: Chave de acesso / corpo da resposta, ou {} em falha.
        """
        url = self.base_url_sefin + f"/dps/{id_dps}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def verificar_existe(self, id_dps):
        """
        Verifica se já existe NFS-e gerada a partir da DPS (sem revelar a chave).

        HEAD /dps/{id}

        Disponível para qualquer certificado digital válido.

        Args:
            id_dps (str): Identificador da DPS (45 caracteres).

        Returns:
            bool: True se a NFS-e foi gerada (HTTP 2xx), False caso contrário.
        """
        url = self.base_url_sefin + f"/dps/{id_dps}"
        response = self.request("HEAD", url=url)
        if response is None:
            return False
        return response.status_code in (200, 201, 204)


class eventos(auth):
    """Registro e consulta de eventos da NFS-e (Sefin Nacional)."""

    def registrar(self, chave_acesso, xml_evento):
        """
        Registra um evento vinculado à NFS-e.

        POST /nfse/{chaveAcesso}/eventos

        O código do evento (6 dígitos) no XML define a operação
        (cancelamento, manifestação, ofício, etc.).

        Args:
            chave_acesso (str): Chave de acesso da NFS-e.
            xml_evento (str): XML do pedido de registro de evento (assinado).

        Returns:
            dict | str: Corpo da resposta ou {} em falha.
        """
        url = self.base_url_sefin + f"/nfse/{chave_acesso}/eventos"
        response = self.request(
            "POST",
            url=url,
            json_data={"xml": xml_evento},
            headers={"Content-Type": "application/json"},
        )
        if response is None:
            return {}
        if response.status_code not in (200, 201):
            return {"status_code": response.status_code, "body": self._parse_response_body(response)}
        return self._parse_response_body(response) or {}

    def consultar_todos(self, chave_acesso):
        """
        Lista todos os eventos vinculados à chave de acesso.

        GET /nfse/{chaveAcesso}/eventos
        """
        url = self.base_url_sefin + f"/nfse/{chave_acesso}/eventos"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_por_tipo(self, chave_acesso, tipo_evento):
        """
        Consulta eventos por chave e tipo.

        GET /nfse/{chaveAcesso}/eventos/{tipoEvento}

        Args:
            chave_acesso (str): Chave de acesso da NFS-e.
            tipo_evento (str): Código do evento (ex.: ``"101101"``).
        """
        url = self.base_url_sefin + f"/nfse/{chave_acesso}/eventos/{tipo_evento}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_por_sequencial(self, chave_acesso, tipo_evento, num_seq):
        """
        Consulta evento específico por chave, tipo e sequencial.

        GET /nfse/{chaveAcesso}/eventos/{tipoEvento}/{numSeqEvento}
        """
        url = (
            self.base_url_sefin
            + f"/nfse/{chave_acesso}/eventos/{tipo_evento}/{num_seq}"
        )
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}


class distribuicao(auth):
    """Distribuição de DF-e para contribuintes (ADN)."""

    def consultar_dfe(self, nsu, cnpj_consulta=None):
        """
        Consulta documentos fiscais a partir do NSU.

        GET /DFe/{NSU}

        Após rejeições E2215/E2230/E2305/E2020 (nenhum documento), aplica
        cooldown automático de 1 hora antes de nova consulta NSU.

        Args:
            nsu (int | str): Número Sequencial Único.
            cnpj_consulta (str, optional): CNPJ diferente do certificado
                (validação por CNPJ raiz).

        Returns:
            dict | str: Documentos encontrados, ou {} / estrutura de erro.
        """
        self._nsu_check_cooldown()

        url = self.base_url_adn + f"/DFe/{nsu}"
        params = {}
        if cnpj_consulta:
            params["cnpj"] = cnpj_consulta

        response = self.request("GET", url=url, params=params)
        if response is None:
            return {}

        body = self._parse_response_body(response)
        codes = self._extract_rejection_codes(body)

        if codes & REJEICOES_NSU_VAZIO:
            self._nsu_apply_cooldown()
            if self.print_error:
                print(
                    f"Nenhum documento a partir do NSU {nsu} "
                    f"(códigos: {sorted(codes & REJEICOES_NSU_VAZIO)}). "
                    "Cooldown de 1 hora aplicado."
                )

        if response.status_code not in (200, 201):
            return {
                "status_code": response.status_code,
                "body": body,
                "rejeicoes": sorted(codes),
            }

        if isinstance(body, dict):
            return body
        return body or {}

    def consultar_eventos(self, chave_acesso):
        """
        Consulta eventos de uma NFS-e no ADN (compartilhamento).

        GET /NFSe/{ChaveAcesso}/Eventos
        """
        url = self.base_url_adn + f"/NFSe/{chave_acesso}/Eventos"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}


class parametros(auth):
    """Parâmetros municipais (Sefin Nacional)."""

    def consultar_convenio(self, codigo_municipio):
        """
        Consulta parâmetros do convênio de um município.

        GET /parametros_municipais/{codigoMunicipio}/convenio
        """
        url = (
            self.base_url_sefin
            + f"/parametros_municipais/{codigo_municipio}/convenio"
        )
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_aliquotas(self, codigo_municipio, codigo_servico):
        """
        Consulta alíquotas, regimes especiais e deduções por subitem.

        GET /parametros_municipais/{codigoMunicipio}/{codigoServico}
        """
        url = (
            self.base_url_sefin
            + f"/parametros_municipais/{codigo_municipio}/{codigo_servico}"
        )
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_retencoes(self, codigo_municipio, cpf_cnpj):
        """
        Consulta retenções a que o contribuinte tem dever de recolher.

        GET /parametros_municipais/{codigoMunicipio}/{CPF/CNPJ}
        """
        url = (
            self.base_url_sefin
            + f"/parametros_municipais/{codigo_municipio}/{cpf_cnpj}"
        )
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_beneficios(self, codigo_municipio, cpf_cnpj):
        """
        Consulta benefícios municipais do contribuinte.

        Nota: a documentação oficial usa o mesmo padrão de path que retenções
        (município + CPF/CNPJ). Em caso de ambiguidade na API, use a Swagger
        do ambiente alvo para confirmar o path exato.
        """
        url = (
            self.base_url_sefin
            + f"/parametros_municipais/{codigo_municipio}/{cpf_cnpj}"
        )
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}


class danfse(auth):
    """Documento Auxiliar da NFS-e (PDF) — ADN."""

    def obter_pdf(self, chave_acesso):
        """
        Obtém o PDF (DANFSE) pela chave de acesso.

        GET /danfse/{chaveAcesso}

        Em HTTP 502/503 retorna None (instabilidade conhecida — NT 008/2026).
        Considere gerar o PDF localmente a partir do XML quando possível.

        Args:
            chave_acesso (str): Chave de acesso da NFS-e.

        Returns:
            bytes | None: Conteúdo do PDF, ou None em falha/indisponibilidade.
        """
        url = self.base_url_danfse + f"/danfse/{chave_acesso}"
        response = self.request(
            "GET",
            url=url,
            headers={"Accept": "application/pdf"},
        )
        if response is None:
            return None
        if response.status_code in (502, 503):
            if self.print_error:
                print(
                    "DANFSE indisponível (502/503). "
                    "Recomendação (NT 008/2026): gerar PDF localmente a partir do XML."
                )
            return None
        if response.status_code not in (200, 201):
            return None
        return response.content


class cnc(auth):
    """Cadastro Nacional de Contribuintes da NFS-e (ADN CNC)."""

    def consultar_cadastro(self, nsu):
        """
        Consulta cadastro CNC a partir do NSU.

        GET /cad/CNC/{nsu}
        """
        url = self.base_url_cnc + f"/cad/CNC/{nsu}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

    def consultar_movimentos(self, nsu):
        """
        Consulta movimentos CNC a partir do NSU.

        GET /mov/CNC/{nsu}
        """
        url = self.base_url_cnc + f"/mov/CNC/{nsu}"
        response = self.request("GET", url=url)
        if response is None or response.status_code not in (200, 201):
            return {}
        return self._parse_response_body(response) or {}

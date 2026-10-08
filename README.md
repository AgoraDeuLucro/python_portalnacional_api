# py_portalnacional

Wrapper não oficial das APIs do **Portal Nacional de NFS-e** (Sistema Nacional da Nota Fiscal de Serviço Eletrônica).

Autenticação via **mTLS** com certificado digital ICP-Brasil (A1 PFX/P12 ou PEM).

## Instalação

```bash
pip install -r requirements.txt
# ou, em modo editável:
pip install -e .
```

## Ambientes

| Ambiente | Valor de `environment` |
|---|---|
| Produção restrita (sandbox) | `"homologacao"` (padrão) |
| Produção oficial | `"producao"` |

| Módulo | Produção | Homologação |
|---|---|---|
| Sefin Nacional | `https://sefin.nfse.gov.br/SefinNacional` | `https://sefin.producaorestrita.nfse.gov.br/API/SefinNacional` |
| ADN Contribuintes | `https://adn.nfse.gov.br/contribuintes` | `https://adn.producaorestrita.nfse.gov.br/contribuintes` |
| DANFSE | `https://adn.nfse.gov.br/danfse` | `https://adn.producaorestrita.nfse.gov.br/danfse` |
| CNC | `https://adn.nfse.gov.br/cnc` | `https://adn.producaorestrita.nfse.gov.br/cnc` |

Documentação Swagger (homologação — contribuintes):  
https://adn.producaorestrita.nfse.gov.br/contribuintes/docs/index.html

## Uso rápido

### Instanciar com certificado A1 (PFX)

```python
from py_portalnacional import nfse, distribuicao, dps

client = nfse(
    cert_path="/caminho/para/certificado.pfx",
    cert_password="senha",
    environment="homologacao",  # ou "producao"
)
```

### Ou com PEM separado

```python
from py_portalnacional import nfse

client = nfse(
    cert_pem="/caminho/cert.pem",
    key_pem="/caminho/key.pem",
    environment="homologacao",
)
```

### Emitir NFS-e (síncrono)

```python
# xml_dps: string UTF-8 do XML da DPS já assinado digitalmente
resultado = client.emitir(xml_dps)
```

### Consultar NFS-e pela chave de acesso

```python
# Chave de acesso: 50 caracteres
nota = client.consultar("NFS...")
```

### Consultar chave a partir do ID da DPS

```python
from py_portalnacional import dps

dps_client = dps(
    cert_path="/caminho/certificado.pfx",
    cert_password="senha",
    environment="homologacao",
)

# ID da DPS: 45 posições (IBGE + tipo inscrição + CPF/CNPJ + série + número)
chave = dps_client.consultar_chave("3304557...")
existe = dps_client.verificar_existe("3304557...")  # HEAD — True/False
```

### Distribuição por NSU (ADN)

```python
from py_portalnacional import distribuicao

dist = distribuicao(
    cert_path="/caminho/certificado.pfx",
    cert_password="senha",
    environment="homologacao",
)

docs = dist.consultar_dfe(nsu=0)
# Opcional: CNPJ de consulta (mesmo CNPJ raiz do certificado)
docs = dist.consultar_dfe(nsu=100, cnpj_consulta="12345678000199")
```

> **Rate limit NSU:** após rejeições `E2215`, `E2230`, `E2305` ou `E2020`  
> (“nenhum documento localizado”), o cliente bloqueia novas consultas NSU por **1 hora**.

### Eventos

```python
from py_portalnacional import eventos

ev = eventos(
    cert_path="/caminho/certificado.pfx",
    cert_password="senha",
    environment="homologacao",
)

# Registrar (XML do pedido de evento assinado)
ev.registrar(chave_acesso, xml_evento)

# Listar todos os eventos da chave (ADN)
ev.consultar_todos(chave_acesso)

# Consultar um evento na Sefin (tipo + sequencial; sequencial 1 quando o tipo não se repete)
ev.consultar_por_sequencial(chave_acesso, "101101", 1)  # cancelamento direto
```

Códigos de evento (referência):

| Código | Evento |
|---|---|
| 101101 | Cancelamento direto (emitente) |
| 105102 | Cancelamento por substituição |
| 203202 | Confirmação do tomador |
| 203206 | Rejeição do tomador |
| 305101 | Cancelamento por ofício (fisco) |
| 305102 | Bloqueio por ofício (fisco) |

### DANFSE (PDF)

```python
from py_portalnacional import danfse

pdf_client = danfse(
    cert_path="/caminho/certificado.pfx",
    cert_password="senha",
    environment="homologacao",
)

pdf_bytes = pdf_client.obter_pdf(chave_acesso)
if pdf_bytes:
    with open("danfse.pdf", "wb") as f:
        f.write(pdf_bytes)
```

> A rota `/danfse` costuma retornar 502/503 sob carga (NT 008/2026).  
> Nesses casos `obter_pdf` retorna `None`.

### Parâmetros municipais e CNC

```python
from py_portalnacional import parametros, cnc

p = parametros(cert_path="...", cert_password="...", environment="homologacao")
p.consultar_convenio("3304557")
p.consultar_aliquotas("3304557", "0101")

c = cnc(cert_path="...", cert_password="...", environment="homologacao")
c.consultar_cadastro(nsu=0)
c.consultar_movimentos(nsu=0)
```

## Módulos

| Classe | Base URL | Principais métodos |
|---|---|---|
| `nfse` | Sefin | `emitir`, `consultar`, `emitir_decisao_judicial`, `emitir_lote_assincrono`, `consultar_lote` |
| `dps` | Sefin | `consultar_chave`, `verificar_existe` |
| `eventos` | Sefin (registro e consulta pontual) e ADN (listagem) | `registrar`, `consultar_todos` (ADN), `consultar_por_sequencial` (Sefin, tipo + sequencial) |
| `distribuicao` | ADN Contribuintes | `consultar_dfe`, `consultar_eventos` |
| `parametros` | Sefin | `consultar_convenio`, `consultar_aliquotas`, `consultar_retencoes`, `consultar_beneficios` |
| `danfse` | ADN DANFSE | `obter_pdf` |
| `cnc` | ADN CNC | `consultar_cadastro`, `consultar_movimentos` |

Todas as classes herdam de `auth` (sessão mTLS + `request()` centralizado).

## Observações

- O XML da DPS/eventos deve estar **assinado digitalmente** (ICP-Brasil) antes do envio.
- Lote assíncrono: no máximo **50** XMLs; polling de recibo com intervalo mínimo de **5 s**.
- Consulta por chave: o XML só é devolvido se o certificado for Prestador, Tomador ou Intermediário.
- Prestador e tomador usam a **mesma rota**; a diferença é a validação de sigilo no certificado mTLS.

## Licença

MIT


# Material de apoio

O primeiro passo é ter o código de sua biblioteca separado em uma pasta



*   meu\_pacote/ # Pasta do projeto
    *   codigos\_da\_biblioteca/ # Diretório onde deve ficar os códigos de sua biblioteca
    *   LICENCE # Um arquivo com a licença da sua lib
    *   [README.MD](http://README.MD) # Uma descrição do projeto
    *   [setup.py](http://setup.py) # Código Python responsável pelo empacotamento



Adicione uma licença

```plain
The MIT License (MIT)

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```



Adicione um readme

```markdown
# Sua descrição aqui
```



Instale a lib setuptools

```plain
pip install setuptools
```



Crie o [setup.py](http://setup.py)

```plain
from setuptools import setup

with open("README.md", "r") as arq:
    readme = arq.read()

setup(name='wrapper-panda-video',
    version='0.0.1',
    license='MIT License',
    author='Caio Sampaio',
    long_description=readme,
    long_description_content_type="text/markdown",
    author_email='caio@pythonando.com.br',
    keywords='panda video',
    description=u'Wrapper não oficial do Panda Video',
    packages=['panda_video'],
    install_requires=['requests'],)
```



Execute o comando

```plain
python3 setup.py sdist
```



Instale o twine para fazer o upload para o pypi

```plain
pip install twine
```



Crie uma conta no pypi



Execute o comando para criar um repositório de teste

```plain
twine upload --repository-url https://test.pypi.org/legacy/ dist/*
```



Ou para criar um repositório oficial:

```plain
twine upload dist/*
```
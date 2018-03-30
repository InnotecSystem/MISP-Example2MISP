# Example2MISP

## Descripción

**Example2MISP** es un script de ejemplo de carga de eventos en MISP desde un fichero .csv


## Instalación

Para ejecutar el **Example2MISP.py** hay que tener instalado *Python 3* en el sistema dado que la librería para conectar con el MISP (*PyMISP*) está programado en ese lenguaje. Además, hay que tener instalado '*pip*' para instalar *PyMISP*:

```
user@machine:~$ sudo apt-get install -y python3 python3-pip
```

Una vez instalado, se puede instalar la librería de conexión con MISP [PyMISP](https://github.com/CIRCL/PyMISP)

```
user@machine:~$ sudo pip install pymisp
```

También hay que instalar otros paquetes para validar URLs, direcciones de correo electrónico y direcciones IP.

```
user@machine:~$ sudo pip install IPy
user@machine:~$ sudo pip install validators
```


## Certificado

Para obtener el certificado .pem, que es el formato que PyMISP requiere, a partir del certificado .p12 (certificado.pem), se debe tener instalado **openssl**:

```
user@machine:~$ sudo apt-get install -y openssl
```

Posteriormente, se deben ejecutar el siguiente comando para obtener el certificado:

```
openssl pkcs12 -in certificado.p12 -out certificado.pem -clcerts -nokeys
```

La clave privada se obtiene con la siguiente instrucción:

```
openssl pkcs12 -in certificado.p12 -out certificado_key.pem -nocerts -nodes
```

Se añade la clave privada al certificado

```
cat certificado_key.pem >> certificado.pem
```

Por limpieza, se puede editar el fichero y quitar las cabeceras que no sean el certificado propiamente dicho pero no es obligatorio.


## Configuración

Antes de empezar, hay que editar el fichero **Example2MISP.py** y cambiar los datos de conexión al MISP contra el que se va a trabajar, el token y la ruta del certificado (si se requiere).

```
misp_url = 'https://misp.organizacion.com/'
misp_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
misp_cert = None
misp_verifycert = False
```


## Uso

El script **Example2MISP.py** lee el fichero **Example2MISP.csv** con los datos y lo procesa. Para ejecutarlo sólo hay que ejecutarlo así:

```
python3 Example2MISP.py
```

El fichero 'Example2MISP.csv' tiene el siguiente formato

```
Id;Tipo;Subtipo;Urls;ISPs;Dominios-IPs;Hash;Fecha de registro;Fecha de cierre
```

y cada campo significa lo siguiente:

- `Id` es un identificador interno que NO se comparte con el resto de los MISP
- `Tipo` es el tipo de evento como puede ser 'Trojan' o 'Phishing'
- `Subtipo` es la subcategoría como podría ser 'Zeus', 'Ransomware' o 'Trickbot / Trickster'
- `Urls` son las URLs o direcciones de correo electrónico que van separados por un pipe '|'
- `ISPs` es el ISP asociado al caso que es una información interna que no se comparte con el resto de los MISP
- `Dominios-IPs` son los dominios y direcciones IP asociados al caso
- `Hash` es el hash MD5 del binario asociado al caso
- `Fecha de registro` es la fecha en la que se dió de alta el caso
- `Fecha de  cierre` es la fecha en la que se cerró el incidente pero no se guarda


## Fichero de ejemplo

```
Id;Tipo;Subtipo;Urls;ISPs;Dominios-IPs;Hash;Fecha de registro;Fecha de cierre
0001;Trojan;Trickbot / Trickster;https://62.109.24.134:443 | http://62.109.24.134 | xxxxx@yyyyy.com;JSC ISPsystem;62.109.24.134 | beefreee.bio;04d804eab55c8af704e74e32f92d8191;28/01/2018 19:31:31;29/01/2018 02:56:12
0002;Phishing;;http://agencia.reise-pavillon-gmbh.de/ | wwwwwwww@zzzzzzzz.org | http://agencia.reise-pavillon-gmbh.de/?http://www.agencia2.com/;1&1 Internet SE;217.160.231.147 | reise-pavillon-gmbh.de | agencia.reise-pavillon-gmbh.de;;14/02/2018 10:36:27;14/02/2018 11:05:06
0003;Trojan;Ransomware;http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/snd.php | http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/load.html | http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/index_2.html | http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/snd2.php | http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/load_1.html | http://kfz-sv-polat.de/ag/75003c824af1dfb4788bb1a0528dd5bb/index.html;Strato AG;81.169.145.94 | kfz-sv-polat.de;20bac7aa46a9d2f0f19e54ed36a9b0fd;14/02/2018 10:42:20;14/02/2018 11:02:59
0004;Trojan;Zeus;https://62.109.29.146:443;JSC ISPsystem;62.109.29.146 | branas.ru.;bce71fda40b33921de7cbec44b64f3e3;02/01/2018 15:34:14;03/01/2018 07:52:20
```

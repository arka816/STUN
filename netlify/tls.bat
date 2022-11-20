set RSABITS=4096
set PASSWORD=MAVIS
set EXPIREDAYS=1825

set PATH_CA=%~dp0cert\ca\
set PATH_SERVER=%~dp0cert\server\
set PATH_TEMP=%~dp0cert\temp\

md %PATH_SERVER% %PATH_TEMP% %PATH_CA%


set OPENSSL_CONF=%~dp0cert\openssl_ca.conf
openssl genrsa -des3 -passout pass:%PASSWORD% -out %PATH_CA%ca.key %RSABITS%
@REM Create Authority Certificate
openssl req -new -x509 -days %EXPIREDAYS% -key %PATH_CA%ca.key -out %PATH_CA%ca.crt -passin pass:%PASSWORD%


set OPENSSL_CONF=%~dp0cert\openssl_server.conf
@REM Generate server key
openssl genrsa -out %PATH_SERVER%server.key %RSABITS%
@REM Generate server cert (certificate signing request - CSR)
openssl req -new -key %PATH_SERVER%server.key -out %PATH_TEMP%server.csr -passout pass:%PASSWORD% 
openssl req -in %PATH_TEMP%server.csr -text -noout 
@REM Sign server cert with self-signed cert
openssl x509 -req -days %EXPIREDAYS% -passin pass:%PASSWORD% -in %PATH_TEMP%server.csr -CA %PATH_CA%ca.crt -CAkey %PATH_CA%ca.key -CAcreateserial -out %PATH_SERVER%server.crt -extensions req_ext -extfile %~dp0cert\openssl_server.conf
openssl x509 -in %PATH_SERVER%server.crt -purpose -text -noout

pause

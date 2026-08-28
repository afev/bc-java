ФОРК BC ДЛЯ ДОБАВЛЕНИЯ ПОДДЕРЖКИ ГОСТ (D)TLS 1.2
--

Форк `BC`: https://github.com/afev/bc-java (https://github.com/afev/bc-java.git)
Последняя ветка: `gost_tls-v.1.84`

Тесты `BC`, которые используются для проверки поддержки: `DTLSClientTest` и `DTLSServerTest`
Эти тесты, как минимум, дополнены регистрациями наших провайдеров (с помощью Security.insertProviderAt(...)), расширен код.

Jar-файлы провайдеров должны быть подключены к проекту `bctls`. Сейчас это папка `csp40`, подключаемая так:
```
implementation fileTree(dir: 'csp40', include: ['*.jar'])
```
в tls/build.gradle.

Папка `csp40` пуста, в нее нужно сложить файлы:
* asn1rt.jar
* ASN1P.jar
* JCP.jar
* JCSP.jar
* samples.jar (кажется, не обязателен)

Сборка `Java CSP` с сайта не подойдет! Необходима наша ночная сборка.

Должен быть установлен `КриптоПро CSP 5.0 R4`!

В дальнейшем для тестов потребуется как минимум один контейнер с серверным сертификатом для сервера.

Стоковый `bctls` содержит константу `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` и несколько ветвлений, но самой реализации не имеет.

В форке сделаны изменения:
* в коде модуля `bctls` - добавлена поддержка `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`. Только `ГОСТ 34.10 2012 (256)`!
* в коде тестов `bctls` - доработаны `DTLSClientTest` и `DTLSServerTest` и добавлены тестовые корневые сертификаты `x509-ca-gost.pem`, `x509-client-gost.pem`, `x509-server-gost.pem` в ресурсы, но самих контейнеров нет

В доработках используются имена алгоритмов `BC`, если подходящие есть в `BC`, и имена `Java CSP` в противном случае.

Сам `btls` в итоге в явном виде не зависит от `Java CSP`, импорты из него есть только в тестах.

С участием `CSP` и `Java CSP` поддерживаются: `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` (0xC100) и `TLS_RSA_WITH_AES_256_GCM_SHA384` (0x009D). Второй криптонабор может потребовать локальной настройки `CSP` или `openssl`, если они в роли сервера.

Вся настройка осуществляется прямо в коде с помощью методов классов `DefaultTlsServer` или `DefaultTlsClient`. В тестах `DTLSClientTest` и `DTLSServerTest` реализуются классы `MockDTLSClient` и `DefaultTlsServer`. 

`DTLSServerTest` – это несильно измененный тест из состава `BC`. В начале есть регистрация наших провайдеров, как приоритетных, чтобы они использовались при обращениях к `JCA`/`JCE` из `bctls`, а также могут быть выставлены некоторые наши специфические параметры.

Обращение к провайдерам обеспечивается с помощью расширения класса `JcaTlsCrypto`. `BcTlsCrypto` должен быть заменен на `JcaTlsCrypto`, чтобы `JCA`/`JCE` вызовы были перенаправлены с `BC` на дефолтный провайдер.

В тесте ожидается получение пакета от клиента, после чего сервер шлет `HelloVerifyRequest` и осуществляется обмен. Тест выполняет действия за один проход, он не универсален и не ждет новых соединений.

В тесте используется класс `MockDTLSServer`. Он расширен так, чтобы можно было выбрать контейнер и работать с двумя криптонаборами на выбор: `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` или `TLS_RSA_WITH_AES_256_GCM_SHA384` (старый криптонабор, можно использовать для отладки в каких-то случаях).

В начале тестов `DTLSClientTest` и `DTLSServerTest` задана очередность провайдеров:

```
System.setProperty("enable_rsa_inverted_byte_order", "true"); // только для иностранной сюиты
// С более высоким приоритетом - Java CSP.
Security.insertProviderAt(new JCSP(), 1);
Security.insertProviderAt(new JCSPRSA(), 2);
Security.insertProviderAt(new JCSPECDSA(), 3);
Security.insertProviderAt(new BouncyCastleProvider(), 4);
Security.insertProviderAt(new BouncyCastleJsseProvider(), 5);
```

Таким образом, `JcaTlsCrypto` сначала обратится к `JCSP`/`JCSPRSA` вместо `Sun` или `BouncyCastleProvider`.

В `MockDTLSServer` расширены методы. Метод `getCertificateRequest()`, если включена клиентская аутентификация, вернет список алгоритмов и имен доверенных корневых сертификатов. Здесь имена соответствуют имени сертификата `x509-ca-gost.pem`.

Если клиент отправит сертификат, то он может быть проверен в `notifyClientCertificate()`.

Сервер может как требовать клиентскую аутентификацию, так и нет. Чтобы требовал, надо реализовать тела функций `getCertificateRequest()` и `notifyClientCertificate()`. В `getCertificateRequest()` надо формировать список доверенных имен корневых сертификатов клиентов и указать алгоритм `gost_sign256`, а в `notifyClientCertificate()` – как-то проверить (или не проверять) клиентский сертификат после его получения. 

Если аутентификация не нужна, то `getCertificateRequest()` может просто вернуть null. Например, сейчас `getCertificateRequest()` создает `CertificateRequest` с указанием имени издателя предполагаемого клиентского сертификата. А в `notifyClientCertificate()`, используя тот факт, что сертификат клиента и его корневой добавлены в ресурсы тестов, производим построение и проверка предполагаемого клиентского сертификата.

В методах `getGOSTEncryptionCredentials()` и `getRSAEncryptionCredentials()` используются тестовые ключевые контейнеры формата `HDIMAGE` (хранение на диске).

Метод `getRSAEncryptionCredentials()` переделан под нужды `Java CSP`, выбирается контейнер `bc_tls_server_rsa` без пароля на диске (в форке его нет).

Новый метод `getGOSTEncryptionCredentials()` добавлен для поддержки ГОСТа, он выбирает ГОСТовый контейнер `bc_tls_server` (`ГОСТ 34.10-2012 (256)`) без пароля на диске (в форке его нет).

Поддерживаемый `MockDTLSServer` протокол задан в `getSupportedVersions()` - это `DTLSv12`. Криптонабор сервера - `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` или `TLS_RSA_WITH_AES_256_GCM_SHA384` - задается в тесте `DTLSServerTest`.

Клиентский `MockDTLSClient` устроен схожим образом, здесь расширен `getClientCredentials()` для выбора клиентского ключа и сертификата на случай клиентской аутентификации. При `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` выбирается контейнер `bc_tls_client` (`ГОСТ 34.10-2012 (256)`) без пароля на диске (в форке его нет), при `TLS_RSA_WITH_AES_256_GCM_SHA384` - `bc_tls_client_rsa` без пароля на диске (в форке его нет).

Поддерживаемый в `MockDTLSClient` протокол - `DTLSv12` в `getSupportedCipherSuites()`. Криптонабор клиента - `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` или `TLS_RSA_WITH_AES_256_GCM_SHA384` - задается в тесте `DTLSClientTest`.

Проверка работоспособности для ГОСТа осуществлялась с помощью утилиты `csptest` из актуальной сборки `CSP`, например,

```
/opt/cprocsp/bin/amd64/csptest -tlsc -server a.b.c.d -port 10443 -proto 8 -ciphers C100 -nocheck -v -v -verbose -udp -contexttype 2 -recvstring hello -sendstring hello
```

Здесь протокол `8` - `DTLS 1.2`, сюита `C100` - `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`. При включенной на сервере клиентской аутентификации на клиенте должны быть установлены корневые сертификаты сервера и клиента, ключевой контейнер клиента и CRL.



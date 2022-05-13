# WebPasswordManager

Projekt bezpiecznej aplikacji webowej służącej jako menadżer haseł.

Aplikacja skupia się na funkcjonalności i bezpieczeństwie.

### Zaimplementowana funkcjonalność i zabezpieczenia:
- restrykcyjna walidacja danych pochodzących z formularza login-hasło.
- przechowywanie hasła chronione funkcją hash, solą i pieprzem.
- możliwość umieszczenia na serwerze haseł dostępnych prywatnie lub dla określonych użytkowników.
- szyfrowanie symetryczne przechowywanych haseł. 
- zabezpieczenie transmisji poprzez wykorzystanie protokołu https.
- możliwość zmiany hasła.
- możliwość odzyskania dostępu w przypadku utraty hasła.
- dodatkowa kontrola spójności sesji.
- wielokrotne wykorzystanie funkcji hash, żeby wydłużyć ataki brute-force na hash.
- dodanie opóźnienia przy weryfikacji hasła w celu wydłużenia ataków zdalnych.

### Użyte narzędzia:
- Python
- HTML
- Flask

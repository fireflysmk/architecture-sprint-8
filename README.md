Запустить все сервисы можно командой

``` sh
docker-compose up -d
```

Далее проходим по url `localhost:3000`
в форме ввода keycloack вводим данные одной из учетных записей:

- в случае ввода валидной учетки одного из prothetic_user при обращении на ручку `/reports` вернется успешный ответ с сообщнием `access_granted`
- в случае ввода любой невалидной учетной записи при обращении на ручку `/reports` вернется 401 код ошибки

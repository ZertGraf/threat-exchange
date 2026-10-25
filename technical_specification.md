Необходимо реализовать веб сервер с REST-интерфейсом для обмена информацией про угрозы на основе OpenAPI спецификации. Перед реализацией необходимо дополнить модель угрозы полями.

```yaml
openapi: 3.0.0
info:
  title: Information Exchange Service
  description: API для обмена информацией об угрозах.
  version: 1.0.0
paths:
  /info/{md5}:
    get:
      summary: Получить информацию об угрозе по MD5
      description: Возвращает полную информацию об угрозе для указанного MD5-хеша.
      operationId: getInfoByMd5
      parameters:
        - name: md5
          in: path
          required: true
          description: MD5-хеш файла (32 символа, шестнадцатеричные цифры)
          schema:
            type: string
            pattern: '^[a-fA-F0-9]{32}$'
            example: "d41d8cd98f00b204e9800998ecf8427e"
      responses:
        '200':
          description: Успешный ответ с информацией об угрозе
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '404':
          description: Угроза с указанным MD5 не найдена
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '400':
          description: Некорректный формат MD5
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
    put:
      summary: Обновить информацию об угрозе по MD5
      description: Заменяет информацию о существующей угрозе
      operationId: updateThreat
      parameters:
        - name: md5
          in: path
          required: true
          description: MD5-хеш обновляемой записи
          schema:
            type: string
            pattern: '^[a-fA-F0-9]{32}$'
            example: "d41d8cd98f00b204e9800998ecf8427e"
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ThreatUpdateRequest'
      responses:
        '200':
          description: Информация успешно обновлена
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '400':
          description: Некорректные данные запроса или MD5
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '404':
          description: Угроза с указанным MD5 не найдена
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
  /info:
    post:
      summary: Создать новую запись об угрозе
      description: Добавляет новую информацию об угрозе. MD5 должен быть уникальным.
      operationId: createThreat
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ThreatCreateRequest'
      responses:
        '201':
          description: Запись успешно создана
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '400':
          description: Некорректные данные запроса (например, невалидный MD5)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '409':
          description: Угроза с таким MD5 уже существует
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
components:
  schemas:
    ThreatCreateRequest:
      type: object
      required:
        - md5
        - name
      properties:
        md5:
          type: string
          pattern: '^[a-fA-F0-9]{32}$'
          description: MD5-хеш файла (32 шестнадцатеричных символа)
          example: "d41d8cd98f00b204e9800998ecf8427e"
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"
    ThreatUpdateRequest:
      type: object
      required:
        - name
      properties:
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"
    ThreatResponse:
      type: object
      properties:
        md5:
          type: string
          pattern: '^[a-fA-F0-9]{32}$'
          description: MD5-хеш
          example: "d41d8cd98f00b204e9800998ecf8427e"
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"
    ErrorResponse:
      type: object
      properties:
        message:
          type: string
          description: Человекочитаемое описание ошибки
          example: "Threat not found"
        details:
          type: string
          description: Дополнительная информация
          example: "No threat with MD5 d41d8cd98f00b204e9800998ecf8427e found"
```

Задание предполагает только реализацию сервиса, но будет плюсом:

1. Наличие юнит и интеграционных тестов
2. Осмысленное дополнение полей, валидация данных
3. Использование docker для развертывания
4. Использование СУБД и библиотек кодогенерации по спеке
5. Документация кода
6. Дополнительная защита сервиса (работа с сертификатами, rate-limit, управление доступом и т.д)

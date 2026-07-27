# 슬라이싱 결과 수동 검토 메모

## 검토 정보

- 검토자: 최주언
- 검토일: 2026/07/23
- 담당 CWE: CWE-89, CWE-369

## 검토 대상 요약

CWE 2개에서 testcase 5개씩 선택

| 번호 | CWE | Testcase index | 대표 Java 파일명 | Flow 유형 |
|---:|---:|---:|---|---|
| 1 | 89 | 457 | CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 2 | 89 | 1203 | CWE89_SQL_Injection__console_readLine_executeQuery_22*.java | b2b, g2b |
| 3 | 89 | 1781 | CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 4 | 89 | 648 | CWE89_SQL_Injection__Property_executeQuery_22*.java | b2b, b2g1, b2g2, g2b |
| 5 | 89 | 1859 | CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 6 | 369 | 929 | CWE369_Divide_by_Zero__int_File_modulo_04.java | g2b1, g2b2 |
| 7 | 369 | 1302 | CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 8 | 369 | 1709 | CWE369_Divide_by_Zero__int_random_divide_07.java | b2b, b2g1, b2g2, g2b1,g2b2 |
| 9 | 369 | 748 | CWE369_Divide_by_Zero__float_zero_divide_08.java | b2b, b2g1, b2g2, g2b1,g2b2 |
| 10 | 369 | 334 | CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java |  |

## Testcase별 검토

### [1] CWE-89 / Testcase 457

- Java 파일명: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java

#### (1) Flow1 b2b

- Source: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:50
- Sink: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:90

**예상 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=38 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=43 | new Properties()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=45 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=47 | streamFileInput = new FileInputStream("../common/config.properties");
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=48 | properties.load(streamFileInput);
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=50 | data = properties.getProperty("data")
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=57 | finally
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=59 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=61 | if (streamFileInput != null)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=63 | streamFileInput.close()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=80 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=85 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=87 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=88 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=90 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=38, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=43, col=41 | new Properties()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=45, col=17 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=47, col=21 | streamFileInput
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=47, col=39 | new FileInputStream("../common/config.properties")
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=48, col=21 | properties
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=48, col=37 | streamFileInput
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=50, col=21 | data = properties.getProperty("data")
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=52, col=17 | catch
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=54, col=21 | IO.logger
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=54, col=35 | Level.WARNING
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=54, col=50 | "Error with stream reading"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=54, col=79 | exceptIO
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=57, col=17 | finally
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=59, col=21 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=61, col=25 | if (streamFileInput != null)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=63, col=29 | streamFileInput.close()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=66, col=21 | catch
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=68, col=25 | IO.logger
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=68, col=39 | Level.WARNING
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=68, col=54 | "Error closing FileInputStream"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=68, col=87 | exceptIO
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=77, col=13 | data
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=77, col=20 | null
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=80, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=85, col=13 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=87, col=17 | dbConnection
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=87, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=88, col=17 | sqlStatement
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=88, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=90, col=17 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 약간 과도
- 근거: 

    - 포함되어야 할 핵심적인 라인은 포함되어 있지만, try-catch-finally의 catch 흐름도 포함됨.

    - 루트 노드가 없는 경우도 있음.

        ex) line=48에서, properties.load(streamFileInput)는 없지만 properties, streamFileInput은 있음.



#### (2) Flow2 b2g1

- Source: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:304
- Sink: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:349

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: 
    - sink를 잘못 지정함.
        ```java
        /* FIX: Use prepared statement and executeQuery (properly) */
        dbConnection = IO.getDBConnection();
        sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
        sqlStatement.setString(1, data);

        resultSet = sqlStatement.executeQuery();

        IO.writeLine(resultSet.getRow()); /* Use ResultSet in some way */
        ```
        첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.




#### (3) Flow3 b2g2

- Source: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:419
- Sink: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:457

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거:
    - sink를 잘못 지정함.
        ```java
        /* FIX: Use prepared statement and executeQuery (properly) */
        dbConnection = IO.getDBConnection();
        sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
        sqlStatement.setString(1, data);
        resultSet = sqlStatement.executeQuery();
        IO.writeLine(resultSet.getRow()); /* Use ResultSet in some way */
        ```
        첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.



#### (4) Flow4 g2b1

- Source: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:152
- Sink: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:166

**예상 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=142 | if (IO.STATIC_FINAL_FIVE != 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=146 | data = null
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=148 | else
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=152 | data = "foo"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=156 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=161 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=163 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=164 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=166 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=142, col=9 | if (IO.STATIC_FINAL_FIVE != 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=146, col=13 | data
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=146, col=20 | null
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=152, col=13 | data
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=152, col=20 | "foo"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=156, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=161, col=13 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=163, col=17 | dbConnection
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=163, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=164, col=17 | sqlStatement
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=164, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=166, col=17 | resultSet
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=166, col=29 | sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



#### (5) Flow5 g2b2

- Source: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:221
- Sink: CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java:240

**예상 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=218 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=221 | data = "foo"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=223 | else
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=227 | data = null
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=230 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=235 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=237 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=238 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=240 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=218, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=221, col=13 | data
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=221, col=20 | "foo"
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=227, col=13 | data
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=227, col=20 | null
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=230, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=235, col=13 | try
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=237, col=17 | dbConnection
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=237, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=238, col=17 | sqlStatement
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=238, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=240, col=17 | resultSet
CWE89_SQL_Injection__PropertiesFile_executeQuery_13.java | line=240, col=29 | sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



### [2] CWE-89 / Testcase 1203

- Java 파일명:
    - CWE89_SQL_Injection__console_readLine_executeQuery_22a.java
    - CWE89_SQL_Injection__console_readLine_executeQuery_22b.java

#### (1) Flow1 b2b

- Source: CWE89_SQL_Injection__console_readLine_executeQuery_22b.java:41
- Sink: CWE89_SQL_Injection__console_readLine_executeQuery_22a.java:87

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source는 badSink() 함수의 sink 부분으로 지정되어 있고, sink는 완전히 다른 곳으로 지정되어 있음.
    - source가 가리키는 곳 (`resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'")`)
        ```java
        public void badSink(String data ) throws Throwable
        {
            if (CWE89_SQL_Injection__console_readLine_executeQuery_22a.badPublicStatic)
            {
                ...
                try
                {
                    dbConnection = IO.getDBConnection();
                    sqlStatement = dbConnection.createStatement();
                    /* POTENTIAL FLAW: data concatenated into SQL statement used in executeQuery(), which could result in SQL Injection */
                    resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
                    IO.writeLine(resultSet.getRow()); /* Use ResultSet in some way */
                }
                ...
        ```
    - sink가 가리키는 곳 (`badPublicStatic = true`)
        ```java
        public class CWE89_SQL_Injection__console_readLine_executeQuery_22a extends AbstractTestCase
        {
            ...
            public void bad() throws Throwable
            {
                ...

                /* NOTE: Tools may report a flaw here because buffread and isr are not closed.  Unfortunately, closing those will close System.in, which will cause any future attempts to read from the console to fail and throw an exception */

                badPublicStatic = true;
                (new CWE89_SQL_Injection__console_readLine_executeQuery_22b()).badSink(data );
            }
        ```


#### (2) Flow4 g2b

- Source: CWE89_SQL_Injection__console_readLine_executeQuery_22a.java:224
- Sink: CWE89_SQL_Injection__console_readLine_executeQuery_22b.java:249

**예상 트레이스**

```text
CWE89_SQL_Injection__console_readLine_executeQuery_22a.java | line=224 | data = "foo"
CWE89_SQL_Injection__console_readLine_executeQuery_22a.java | line=227 | (new CWE89_SQL_Injection__console_readLine_executeQuery_22b()).goodG2BSink(data )

CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=237 | public void goodG2BSink(String data ) throws Throwable
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=239 | if (CWE89_SQL_Injection__console_readLine_executeQuery_22a.goodG2BPublicStatic)
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=244 | try
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=246 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=247 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=249 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__console_readLine_executeQuery_22a.java | line=224, col=9 | data
CWE89_SQL_Injection__console_readLine_executeQuery_22a.java | line=224, col=16 | "foo"
CWE89_SQL_Injection__console_readLine_executeQuery_22a.java | line=227, col=84 | data

CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=237, col=29 | String data
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=239, col=9 | if (CWE89_SQL_Injection__console_readLine_executeQuery_22a.goodG2BPublicStatic)
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=244, col=13 | try
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=246, col=17 | dbConnection
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=246, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=247, col=17 | sqlStatement
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=247, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=249, col=17 | resultSet
CWE89_SQL_Injection__console_readLine_executeQuery_22b.java | line=249, col=29 | sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: goodG2BSink() 함수 이름까지는 안 뽑혔지만 인자/매개변수는 포함되었고, 나머지는 대부분 잘 추출함.



### [3] CWE-89 / Testcase 1781

- Java 파일명: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java

#### (1) Flow1 b2b

- Source: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:43
- Sink: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:61

**예상 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=37 | HttpServletRequest request
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=40 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=43 | data = request.getParameter("name")
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=49 | data = null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=52 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=56 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=58 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=59 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=61 | int rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=37, col=21 | HttpServletRequest request
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=40, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=43, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=43, col=20 | request.getParameter("name")
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=49, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=49, col=20 | null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=52, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=56, col=13 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=58, col=17 | dbConnection
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=58, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=59, col=17 | sqlStatement
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=59, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=61, col=21 | int rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



#### (2) Flow2 b2g1

- Source: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:229
- Sink: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:252

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: sink를 잘못 지정함.
    ```java
    /* FIX: Use prepared statement and executeUpdate (properly) */
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("insert into users (status) values ('updated') where name=?");
    sqlStatement.setString(1, data);

    int rowCount = sqlStatement.executeUpdate();

    IO.writeLine("Updated " + rowCount + " rows successfully.");
    ```
    첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.



#### (3) Flow3 b2g2

- Source: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:301
- Sink: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:317

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: sink를 잘못 지정함.
    ```java
    /* FIX: Use prepared statement and executeUpdate (properly) */
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("insert into users (status) values ('updated') where name=?");
    sqlStatement.setString(1, data);
    int rowCount = sqlStatement.executeUpdate();
    IO.writeLine("Updated " + rowCount + " rows successfully.");
    ```
    첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.



#### (4) Flow4 g2b1

- Source: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:111
- Sink: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:124

**예상 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=101 | if (this.privateFalse)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=105 | data = null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=111 | data = "foo"
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=115 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=119 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=121 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=122 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=124 | rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=101, col=9 | if (this.privateFalse)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=105, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=105, col=20 | null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=111, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=111, col=20 | "foo"
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=115, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=119, col=13 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=121, col=17 | dbConnection
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=121, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=122, col=17 | sqlStatement
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=122, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=124, col=21 | rowCount
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=124, col=32 | sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



#### (5) Flow5 g2b2

- Source: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:167
- Sink: CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java:185

**예상 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=164 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=167 | data = "foo"
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=173 | data = null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=176, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=180, col=13 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=182, col=17 | dbConnection
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=182, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=183, col=17 | sqlStatement
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=183, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=185, col=21 | int rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=164, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=167, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=167, col=20 | "foo"
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=173, col=13 | data
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=173, col=20 | null
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=176, col=9 | if (this.privateTrue)
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=180, col=13 | try
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=182, col=17 | dbConnection
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=182, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=183, col=17 | sqlStatement
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=183, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_05.java | line=185, col=21 | int rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



### [4] CWE-89 / Testcase 648

- Java 파일명:
    - CWE89_SQL_Injection__Property_executeQuery_22a.java
    - CWE89_SQL_Injection__Property_executeQuery_22b.java
    
#### (1) Flow1 b2b

- Source: CWE89_SQL_Injection__Property_executeQuery_22a.java:35
- Sink: CWE89_SQL_Injection__Property_executeQuery_22b.java:41

**예상 트레이스**

```text
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=35 | data = System.getProperty("user.home")
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=38 | (new CWE89_SQL_Injection__Property_executeQuery_22b()).badSink(data )

CWE89_SQL_Injection__Property_executeQuery_22b.java | line=29 | public void badSink(String data ) throws Throwable
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=31 | if (CWE89_SQL_Injection__Property_executeQuery_22a.badPublicStatic)
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=36 | try
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=38 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=39 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=41 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=35, col=9 | data
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=35, col=16 | System.getProperty("user.home")
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=38, col=72 | data

CWE89_SQL_Injection__Property_executeQuery_22b.java | line=29, col=25 | String data
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=31, col=9 | if (CWE89_SQL_Injection__Property_executeQuery_22a.badPublicStatic)
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=36, col=13 | try
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=38, col=17 | dbConnection
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=38, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=39, col=17 | sqlStatement
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=39, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=41, col=17 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: badSink() 함수 이름까지는 안 뽑혔지만 인자/매개변수는 포함되었고, 나머지는 대부분 잘 추출함.



#### (2) Flow2 b2g1

- Source: CWE89_SQL_Injection__Property_executeQuery_22a.java:61
- Sink: CWE89_SQL_Injection__Property_executeQuery_22b.java:114

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: sink를 잘못 지정함.
    ```java
    /* FIX: Use prepared statement and executeQuery (properly) */
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
    sqlStatement.setString(1, data);

    resultSet = sqlStatement.executeQuery();

    IO.writeLine(resultSet.getRow()); /* Use ResultSet in some way */
    ```
    첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.



#### (3) Flow3 b2g2

- Source: CWE89_SQL_Injection__Property_executeQuery_22a.java:74
- Sink: CWE89_SQL_Injection__Property_executeQuery_22b.java:179

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: sink를 잘못 지정함.
    ```java
    /* FIX: Use prepared statement and executeQuery (properly) */
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
    sqlStatement.setString(1, data);
    resultSet = sqlStatement.executeQuery();
    IO.writeLine(resultSet.getRow()); /* Use ResultSet in some way */
    ```
    첫번째가 아니라 세번째 라인(`sqlStatement.setString(1, data)`)을 sink로 지정해야 함.



#### (4) Flow4 g2b

- Source: CWE89_SQL_Injection__Property_executeQuery_22a.java:86
- Sink: CWE89_SQL_Injection__Property_executeQuery_22b.java:249

**예상 트레이스**

```text
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=86 | data = "foo"
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=89 | (new CWE89_SQL_Injection__Property_executeQuery_22b()).goodG2BSink(data )

CWE89_SQL_Injection__Property_executeQuery_22b.java | line=237 | public void goodG2BSink(String data ) throws Throwable
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=239 | if (CWE89_SQL_Injection__Property_executeQuery_22a.goodG2BPublicStatic)
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=244 | try
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=246 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=247 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=249 | resultSet = sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=86, col=9 | data
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=86, col=16 | "foo"
CWE89_SQL_Injection__Property_executeQuery_22a.java | line=89, col=76 | data

CWE89_SQL_Injection__Property_executeQuery_22b.java | line=237, col=29 | String data
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=239, col=9 | if (CWE89_SQL_Injection__Property_executeQuery_22a.goodG2BPublicStatic)
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=244, col=13 | try
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=246, col=17 | dbConnection
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=246, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=247, col=17 | sqlStatement
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=247, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=249, col=17 | resultSet
CWE89_SQL_Injection__Property_executeQuery_22b.java | line=249, col=29 | sqlStatement.executeQuery("select * from users where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: goodG2BSink() 함수 이름까지는 안 뽑혔지만 인자/매개변수는 포함되었고, 나머지는 대부분 잘 추출함.



### [5] CWE-89 / Testcase 1859

- Java 파일명:
    - CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java

#### (1) Flow1 b2b

- Source: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:38
- Sink: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:67

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함.
    ``` java
    /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
    {
        StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
        while (tokenizer.hasMoreTokens())
        ...
    }
    ```
    `{`가 아니라 그 다음 라인(`StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&")`)을 source로 지정해야 함.



#### (2) Flow2 b2g1

- Source: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:256
- Sink: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:290

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함.
    ``` java
    /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
    {
        StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
        while (tokenizer.hasMoreTokens())
        ...
    }
    ```
    `{`가 아니라 그 다음 라인(`StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&")`)을 source로 지정해야 함.



#### (3) Flow3 b2g2

- Source: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:347
- Sink: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:374

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함.
    ``` java
    /* POTENTIAL FLAW: Parse id param out of the URL querystring (without using getParameter()) */
    {
        StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&");
        while (tokenizer.hasMoreTokens())
        ...
    }
    ```
    `{`가 아니라 그 다음 라인(`StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), "&")`)을 source로 지정해야 함.



#### (4) Flow4 g2b1

- Source: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:124
- Sink: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:137

**예상 트레이스**

```text
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=114 | if (IO.STATIC_FINAL_FALSE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=118 | data = null
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=124 | data = "foo"
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=128 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=132 | try
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=134 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=135 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=137 | result = sqlStatement.execute("insert into users (status) values ('updated') where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=114, col=9 | if (IO.STATIC_FINAL_FALSE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=118, col=13 | data
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=118, col=20 | null
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=124, col=13 | data
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=124, col=20 | "foo"
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=128, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=132, col=13 | try
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=134, col=17 | dbConnection
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=134, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=135, col=17 | sqlStatement
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=135, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=137, col=25 | result
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=137, col=34 | sqlStatement.execute("insert into users (status) values ('updated') where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



#### (5) Flow5 g2b2

- Source: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:187
- Sink: CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java:205

**예상 트레이스**

```text
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=184 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=187 | data = "foo"
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=193 | data = null
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=196 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=200 | try
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=202 | dbConnection = IO.getDBConnection()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=203 | sqlStatement = dbConnection.createStatement()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=205 | Boolean result = sqlStatement.execute("insert into users (status) values ('updated') where name='" + data + "'")
```

**실제 트레이스**

```text
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=184, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=187, col=13 | data
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=187, col=20 | "foo"
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=193, col=13 | data
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=193, col=20 | null
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=196, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=200, col=13 | try
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=202, col=17 | dbConnection
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=202, col=32 | IO.getDBConnection()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=203, col=17 | sqlStatement
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=203, col=32 | dbConnection.createStatement()
CWE89_SQL_Injection__getQueryString_Servlet_execute_09.java | line=205, col=25 | Boolean result = sqlStatement.execute("insert into users (status) values ('updated') where name='" + data + "'")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



### [6] CWE-369 / Testcase 929

- Java 파일명: CWE369_Divide_by_Zero__int_File_modulo_04.java

#### (1) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__int_File_modulo_04.java:147
- Sink: CWE369_Divide_by_Zero__int_File_modulo_04.java:155

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=137 | if (PRIVATE_STATIC_FINAL_FALSE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=141 | data = 0
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=147 | data = 2
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=151 | if (PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=155 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=137, col=9 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_FALSE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=141, col=13 | data
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=141, col=20 | 0
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=147, col=13 | data
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=147, col=20 | 2
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=151, col=9 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=155, col=13 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



#### (2) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__int_File_modulo_04.java:166
- Sink: `CWE369_Divide_by_Zero__int_File_modulo_04.java:179

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=163 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=166 | data =2
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=172 | data = 0
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=175 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=179 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=163, col=9 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=166, col=13 | data
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=166, col=20 | 2
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=172, col=13 | data
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=172, col=20 | 0
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=175, col=9 | if (CWE369_Divide_by_Zero__int_File_modulo_04.PRIVATE_STATIC_FINAL_TRUE)
CWE369_Divide_by_Zero__int_File_modulo_04.java | line=179, col=13 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그 외에는 적절함.



### [7] CWE-369 / Testcase 1302

- Java 파일명: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:51
- Sink: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:108

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=39 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=41 | data = Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=46 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=48 | readerInputStream = new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=49 | readerBuffered = new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=51 | stringNumber = readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=52 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=54 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=56 | data = Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=69 | finally
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=70 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=72 | if (readerBuffered != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=74 | readerBuffered.close()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=82 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=84 | if (readerInputStream != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=86 | readerInputStream.close()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=101 | data = 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=104 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=108 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=36, col=5 | this
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=39, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=41, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=41, col=20 | Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=46, col=17 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=48, col=21 | readerInputStream
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=48, col=41 | new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=49, col=21 | readerBuffered
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=49, col=38 | new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=51, col=28 | stringNumber
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=51, col=43 | readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=52, col=21 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=54, col=25 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=56, col=29 | data = Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=58, col=25 | catch
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=60, col=29 | IO.logger.log(Level.WARNING, "Number format exception parsing data from string", exceptNumberFormat)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=64, col=17 | catch
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=66, col=21 | IO.logger
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=66, col=35 | Level.WARNING
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=66, col=50 | "Error with stream reading"
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=66, col=79 | exceptIO
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=69, col=17 | finally
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=70, col=21 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=72, col=25 | if (readerBuffered != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=74, col=29 | readerBuffered.close()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=77, col=21 | catch
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=79, col=25 | IO.logger
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=79, col=39 | Level.WARNING
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=79, col=54 | "Error closing BufferedReader"
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=79, col=86 | exceptIO
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=82, col=21 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=84, col=25 | if (readerInputStream != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=86, col=29 | readerInputStream.close()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=89, col=21 | catch
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=91, col=25 | IO.logger
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=91, col=39 | Level.WARNING
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=91, col=54 | "Error closing InputStreamReader"
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=91, col=89 | exceptIO
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=101, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=101, col=20 | 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=104, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=108, col=13 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**비교 결과**

- 추출 범위: 약간 과도
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그리고 예외 발생 시 에러를 출력하는 흐름(catch)까지 포함됨.



#### (2) Flow2 b2g1

- Source: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:178
- Sink: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:240

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=166 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=168 | data = Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=173 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=175 | readerInputStream = new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=176 | readerBuffered = new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=178 | stringNumber = readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=179 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=181 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=183 | data = Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=228 | data = 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=231 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=240 | if (data != 0)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=242 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=163, col=5 | this
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=166, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=168, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=168, col=20 | Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=173, col=17 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=175, col=21 | readerInputStream
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=175, col=41 | new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=176, col=21 | readerBuffered
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=176, col=38 | new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=178, col=28 | stringNumber
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=178, col=43 | readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=179, col=21 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=181, col=25 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=183, col=29 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=183, col=36 | Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=228, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=228, col=20 | 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=231, col=9 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=240, col=13 | if (data != 0)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100을 data로 나누는 부분(sink)이 포함되지 않음.



#### (3) Flow3 b2g2

- Source: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:268
- Sink: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:324

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=256 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=258 | data = Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=263 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=265 | readerInputStream = new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=266 | readerBuffered = new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=268 | stringNumber = readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=269 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=271 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=273 | data = Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=318 | data = 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=321 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=324 | if (data != 0)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=326 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=253, col=5 | this
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=256, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=258, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=258, col=20 | Integer.MIN_VALUE
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=263, col=17 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=265, col=21 | readerInputStream
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=265, col=41 | new InputStreamReader(System.in, "UTF-8")
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=266, col=21 | readerBuffered
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=266, col=38 | new BufferedReader(readerInputStream)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=268, col=28 | stringNumber
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=268, col=43 | readerBuffered.readLine()
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=269, col=21 | if (stringNumber != null)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=271, col=25 | try
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=273, col=29 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=273, col=36 | Integer.parseInt(stringNumber.trim())
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=318, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=318, col=20 | 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=321, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=324, col=13 | if (data != 0)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100을 data로 나누는 부분(sink)이 포함되지 않음.



#### (4) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:126
- Sink: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:134

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=116 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=120 | data = 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=126 | data = 2
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=130 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=134 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=113, col=5 | this
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=116, col=9 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=120, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=120, col=20 | 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=126, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=126, col=20 | 2
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=130, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=134, col=13 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그외에는 적절함.



#### (5) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:145
- Sink: CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java:158

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=142 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=145 | data = 2
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=151 | data = 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=154 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=158 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=139, col=5 | this
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=142, col=9 | if (privateFive == 5)CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=145, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=145, col=20 | 2
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=151, col=13 | data
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=151, col=20 | 0
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=154, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_console_readLine_modulo_07.java | line=158, col=13 | IO.writeLine("100%" + data + " = " + (100 % data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그외에는 적절함.



### [8] CWE-369 / Testcase 1709

- Java 파일명: CWE369_Divide_by_Zero__int_random_divide_07.java

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__int_random_divide_07.java:38
- Sink: CWE369_Divide_by_Zero__int_random_divide_07.java:51

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=35 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38 | data = (new SecureRandom()).nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=44 | data = 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=47 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=51 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=32, col=5 | this
CWE369_Divide_by_Zero__int_random_divide_07.java | line=35, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38, col=20 | this.nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38, col=21 | <empty>
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38, col=21 | $obj0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=38, col=21 | new SecureRandom()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=44, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=44, col=20 | 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=47, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=51, col=13 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 그외에는 적절함.
    - `$obj0`, `<empty>`는 `new SecureFandom()` 호출을 내부적으로 표현한 중간 객체 노드이기 때문에 트레이스에선 제외해도 괜찮을 것으로 보임.



#### (2) Flow2 b2g1

- Source: CWE369_Divide_by_Zero__int_random_divide_07.java:112
- Sink: CWE369_Divide_by_Zero__int_random_divide_07.java:130

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=109 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112 | data = (new SecureRandom()).nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=118 | data = 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=121 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=130 | if (data != 0)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=132 | IO.writeLine("100/" + data + " = " + (100 / data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=106, col=5 | this
CWE369_Divide_by_Zero__int_random_divide_07.java | line=109, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112, col=20 | this.nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112, col=21 | $obj1
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112, col=21 | <empty>
CWE369_Divide_by_Zero__int_random_divide_07.java | line=112, col=21 | new SecureRandom()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=118, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=118, col=20 | 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=121, col=9 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=130, col=13 | if (data != 0)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100을 data로 나누는 부분(sink)이 포함되지 않음.



#### (3) Flow3 b2g2

- Source: CWE369_Divide_by_Zero__int_random_divide_07.java:149
- Sink: CWE369_Divide_by_Zero__int_random_divide_07.java:161

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=146 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149 | data = (new SecureRandom()).nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=155 | data = 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=158 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=161 | if (data != 0)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=163 | IO.writeLine("100/" + data + " = " + (100 / data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=143, col=5 | this
CWE369_Divide_by_Zero__int_random_divide_07.java | line=146, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149, col=20 | this.nextInt()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149, col=21 | new SecureRandom()
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149, col=21 | $obj2
CWE369_Divide_by_Zero__int_random_divide_07.java | line=149, col=21 | <empty>
CWE369_Divide_by_Zero__int_random_divide_07.java | line=155, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=155, col=20 | 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=158, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=161, col=13 | if (data != 0)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100을 data로 나누는 부분(sink)이 포함되지 않음.



#### (4) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__int_random_divide_07.java:69
- Sink: CWE369_Divide_by_Zero__int_random_divide_07.java:77

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=59 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=63 | data = 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=69 | data = 2
CWE369_Divide_by_Zero__int_random_divide_07.java | line=73 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=77 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=56, col=5 | this
CWE369_Divide_by_Zero__int_random_divide_07.java | line=59, col=9 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=63, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=63, col=20 | 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=69, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=69, col=20 | 2
CWE369_Divide_by_Zero__int_random_divide_07.java | line=73, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=77, col=13 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨.



#### (5) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__int_random_divide_07.java:88
- Sink: CWE369_Divide_by_Zero__int_random_divide_07.java:101

**예상 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=85 | if (privateFive != 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=88 | data = 2
CWE369_Divide_by_Zero__int_random_divide_07.java | line=94 | data = 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=97 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=101 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__int_random_divide_07.java | line=82, col=5 | this
CWE369_Divide_by_Zero__int_random_divide_07.java | line=85, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=88, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=88, col=20 | 2
CWE369_Divide_by_Zero__int_random_divide_07.java | line=94, col=13 | data
CWE369_Divide_by_Zero__int_random_divide_07.java | line=94, col=20 | 0
CWE369_Divide_by_Zero__int_random_divide_07.java | line=97, col=9 | if (privateFive == 5)
CWE369_Divide_by_Zero__int_random_divide_07.java | line=101, col=13 | IO.writeLine("bad: 100/" + data + " = " + (100 / data) + "\n")
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨.



### [9] CWE-369 / Testcase 748

- Java 파일명: CWE369_Divide_by_Zero__float_zero_divide_08.java

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__float_zero_divide_08.java:41
- Sink: CWE369_Divide_by_Zero__float_zero_divide_08.java:53

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=39 | if (privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=41 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=47 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=50 | if (privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=53 | int result = (int) (100.0 / data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=36, col=5 | this
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=39, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=41, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=41, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=47, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=47, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=50, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=53, col=17 | int result = (int) (100.0 / data)
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨.



#### (2) Flow2 b2g1

- Source: CWE369_Divide_by_Zero__float_zero_divide_08.java:114
- Sink: CWE369_Divide_by_Zero__float_zero_divide_08.java:132

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=112 | if (privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=114 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=120 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=123 | if (privateReturnsFalse())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=132 | if (Math.abs(data) > 0.000001)
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=134 | result = (int)(100.0 / data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=109, col=5 | this
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=112, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=114, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=114, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=120, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=120, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=123, col=9 | if (this.privateReturnsFalse())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=132, col=13 | if (Math.abs(data) > 0.000001)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100.0을 data로 나누는 부분(sink)이 포함되지 않음.



#### (3) Flow3 b2g2

- Source: CWE369_Divide_by_Zero__float_zero_divide_08.java:151
- Sink: CWE369_Divide_by_Zero__float_zero_divide_08.java:163

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=149 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=151 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=157 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=160 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=163 | if (Math.abs(data) > 0.000001)
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=165 | int result = (int)(100.0 / data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=146, col=5 | this
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=149, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=151, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=151, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=157, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=157, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=160, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=163, col=13 | if (Math.abs(data) > 0.000001)
```

**비교 결과**

- 추출 범위: 부족
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨. 100.0을 data로 나누는 부분(sink)이 포함되지 않음.



#### (4) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__float_zero_divide_08.java:72
- Sink: CWE369_Divide_by_Zero__float_zero_divide_08.java:79

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=62 | if (this.privateReturnsFalse())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=66 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=72 | data = 2.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=76 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=79 | int result = (int) (100.0 / data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=59, col=5 | this
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=62, col=9 | if (this.privateReturnsFalse())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=66, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=66, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=72, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=72, col=20 | 2.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=76, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=79, col=17 | result
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=79, col=26 | (int) (100.0 / data)
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨.



#### (5) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__float_zero_divide_08.java:91
- Sink: CWE369_Divide_by_Zero__float_zero_divide_08.java:103

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=88, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=91, col=13 | data = 2.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=97, col=13 | data = 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=100, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=103, col=17 | int result = (int) (100.0 / data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=85, col=5 | this
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=88, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=91, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=91, col=20 | 2.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=97, col=13 | data
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=97, col=20 | 0.0f
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=100, col=9 | if (this.privateReturnsTrue())
CWE369_Divide_by_Zero__float_zero_divide_08.java | line=103, col=17 | int result = (int) (100.0 / data)
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나, else가 있는 라인은 추출 안 됨.



### [10] CWE-369 / Testcase 334

- Java 파일명: CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java

#### (1) Flow3 g2b

- Source: CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java:115
- Sink: CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java:118

**예상 트레이스**

```text
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=115 | data = 2.0f
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=118 | result = (int) (100.0 % data)
```

**실제 트레이스**

```text
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=115, col=9 | data
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=115, col=16 | 2.0f
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=118, col=13 | result
CWE369_Divide_by_Zero__float_URLConnection_modulo_01.java | line=118, col=22 | (int) (100.0 % data)
```

**비교 결과**

- 추출 범위: 적절
- 근거: 적절하게 추출됨.



## 요약

- 정상적으로 추출된 flow 수 : 29개 (CWE-89 11개 + CWE-369 18개)
- 추출 실패한 flow 수 : 10개 (CWE-89 10개)
    - source/sink 잘못 지정한 경우가 대부분
    - 한 케이스에서는 source와 sink가 있는 파일이 바뀐 것을 확인
- 수정이 필요한 부분
    - 루트 노드가 없는 경우가 많음.    ex) properties.load(streamFileInput)는 없지만 properties, streamFileInput은 있음.
    - if-else의 else 내부 코드가 포함되는데 else가 있는 라인은 포함되지 않아, if / else 내부의 코드가 구분되지 않는 문제가 있음.
    - try-catch 구문에서 불필요한 에러 출력 코드까지 포함됨.
    - `$obj0`, `<empty>` 등 중간 객체 노드가 표시되는 경우가 있음.
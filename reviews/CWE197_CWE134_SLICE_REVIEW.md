# 슬라이싱 결과 수동 검토 메모

## 검토 정보

- 검토자: Shakhakarmi Urusha
- 검토일: 2026/07/24
- 담당 CWE: CWE-197, CWE-134

## 검토 대상 요약

CWE 2개에서 testcase 5개씩 선택

| 번호 | CWE | Testcase index | 대표 Java 파일명 | Flow 유형 |
|---:|---:|---:|---|---|
| 1 | 197 | 327 | CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | g2b |
| 2 | 197 | 570_flow1 | CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | b2b |
| 3 | 197 | 319_flow2 | CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | g2b |
| 4 | 197 | 866_flow2 | CWE197_Numeric_Truncation_Error__short_File_15.java | g2b1 |
| 5 | 197 | 327_flow2 | CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | g2b |
| 6 | 134 | 605_flow1 | CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | b2b |
| 7 | 134 | 96_flow3 | CWE134_Uncontrolled_Format_String__File_format_42.java | g2b |
| 8 | 134 | 433_flow1 | CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | b2b |
| 9 | 134 | 33_flow2 | CWE134_Uncontrolled_Format_String__Environment_format_72a.java | b2g |
| 10 | 134 | 31_flow2 | CWE134_Uncontrolled_Format_String__Environment_format_68a.java | b2g |

## Testcase별 검토

### [1] CWE-197 / Testcase 327_flow2

- Java 파일명:
    - CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java
    - CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java

#### (1) Flow2 g2b

- Source: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java:110
- Sink: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java:39

**예상 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=110 | data = 2;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=112 | (new CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b()).goodG2BSink();
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=33 | public void goodG2BSink() throws Throwable
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=35 | int data = CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.data;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39 | IO.writeLine((byte)data);
```

**실제 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=110 | data = 2;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=35 | int data = CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.data;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=13 | IO.writeLine((byte) data)
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=13 | IO
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39 | (byte) data
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39 | IO.writeLine((byte)data);
```

**비교 결과**

- 추출 범위: 적절
- 근거: goodG2BSink() 호출과 메서드 선언 라인은 포함되지 않았으며, source 대입은 리터럴 값 2로만 표현됨.

### [2] CWE-197 / Testcase 570_flow1

- Java 파일명:
    - CWE197_Numeric_Truncation_Error__int_database_to_short_15.java

#### (1) Flow1 b2b

- Source: CWE197_Numeric_Truncation_Error__int_database_to_short_15.java:50
- Sink: CWE197_Numeric_Truncation_Error__int_database_to_short_15.java:117

**예상 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=33 | switch (6)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=36 | data = Integer.MIN_VALUE;
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=42 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=45 | connection = IO.getDBConnection();
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=47 | preparedStatement = connection.prepareStatement("select name from users where id=0");
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=48 | resultSet = preparedStatement.executeQuery();
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=50 | String stringNumber = resultSet.getString(1);
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=51 | if (stringNumber != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=53 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55 | data = Integer.parseInt(stringNumber.trim());
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=67 | finally
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=70 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=72 | if (resultSet != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=74 | resultSet.close();
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=82 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=84 | if (preparedStatement != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=86 | preparedStatement.close();
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=94 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=96 | if (connection != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=98 | connection.close();
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=117 | IO.writeLine((short)data);
```

**실제 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=33, col=9 | switch(6)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=33, col=17 | 6
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=36, col=13 | data
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=36, col=20 | Integer.MIN_VALUE
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=42, col=17 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=45, col=21 | connection
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=45, col=34 | IO
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=45, col=34 | IO.getDBConnection()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=47, col=21 | preparedStatement
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=47, col=41 | connection.prepareStatement("select name from users where id=0")
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=47, col=41 | connection
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=47, col=69 | "select name from users where id=0"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=48, col=21 | resultSet
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=48, col=33 | preparedStatement.executeQuery()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=48, col=33 | preparedStatement
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=50, col=28 | stringNumber
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=50, col=43 | resultSet.getString(1)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=50, col=43 | resultSet
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=50, col=63 | 1
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=51, col=21 | if (stringNumber != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=51, col=25 | stringNumber
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=51, col=25 | stringNumber != null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=51, col=41 | null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=53, col=25 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=29 | data
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=29 | data = Integer.parseInt(stringNumber.trim())
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=36 | Integer
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=36 | Integer.parseInt(stringNumber.trim())
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=53 | stringNumber
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=55, col=53 | stringNumber.trim()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=57, col=25 | catch
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=59, col=29 | IO.logger
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=59, col=29 | IO.logger.log(Level.WARNING, "Number format exception parsing data from string", exceptNumberFormat)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=59, col=43 | Level.WARNING
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=59, col=58 | "Number format exception parsing data from string"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=59, col=110 | exceptNumberFormat
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=63, col=17 | catch
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=65, col=21 | IO.logger
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=65, col=35 | Level.WARNING
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=65, col=50 | "Error with SQL statement"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=65, col=78 | exceptSql
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=68, col=17 | finally
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=70, col=21 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=72, col=25 | if (resultSet != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=72, col=29 | resultSet != null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=72, col=29 | resultSet
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=72, col=42 | null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=74, col=29 | resultSet.close()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=74, col=29 | resultSet
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=77, col=21 | catch
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=79, col=25 | IO.logger
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=79, col=39 | Level.WARNING
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=79, col=54 | "Error closing ResultSet"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=79, col=81 | exceptSql
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=82, col=21 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=84, col=25 | if (preparedStatement != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=84, col=29 | preparedStatement != null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=84, col=29 | preparedStatement
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=84, col=50 | null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=86, col=29 | preparedStatement.close()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=86, col=29 | preparedStatement
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=89, col=21 | catch
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=91, col=25 | IO.logger
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=91, col=39 | Level.WARNING
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=91, col=54 | "Error closing PreparedStatement"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=91, col=89 | exceptSql
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=94, col=21 | try
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=96, col=25 | if (connection != null)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=96, col=29 | connection != null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=96, col=29 | connection
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=96, col=43 | null
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=98, col=29 | connection.close()
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=98, col=29 | connection
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=101, col=21 | catch
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=103, col=25 | IO.logger
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=103, col=39 | Level.WARNING
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=103, col=54 | "Error closing Connection"
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=103, col=82 | exceptSql
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=111, col=13 | data
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=111, col=20 | 0
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=117, col=13 | IO
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=117, col=13 | IO.writeLine((short) data)
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=117, col=26 | (short) data
CWE197_Numeric_Truncation_Error__int_database_to_short_15.java | line=117, col=33 | data
```

**비교 결과**

- 추출 범위: 과도

### [3] CWE-197 / Testcase 319_flow2

- Java 파일명:
    - CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java

#### (1) Flow2 g2b

- Source: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java:138
- Sink: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java:127

**예상 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=138 | data = 2;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=140 | this.dataGoodG2B = data;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=141 | this.goodG2BSink();
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=121 | private void goodG2BSink() throws Throwable
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=123 | int data = dataGoodG2B;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=127 | IO.writeLine((byte)data);
```

**실제 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=138 | data = 2
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=140 | this.dataGoodG2B = data
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=141 | this.goodG2BSink()
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=121 | goodG2BSink(this)
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=123 | int data = dataGoodG2B
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=127 | (byte) data
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_45.java | line=127 | IO.writeLine((byte) data)
```

**비교 결과**

- 추출 범위: 적절

### [4] CWE-197 / Testcase 866_flow2

- Java 파일명:
    - CWE197_Numeric_Truncation_Error__short_File_15.java

#### (1) Flow2 g2b1

- Source: CWE197_Numeric_Truncation_Error__short_File_15.java:138
- Sink: CWE197_Numeric_Truncation_Error__short_File_15.java:144

**예상 트레이스**

```text
CWE197_Numeric_Truncation_Error__short_File_15.java | line=129 | switch (5)
CWE197_Numeric_Truncation_Error__short_File_15.java | line=131 | case 6:
CWE197_Numeric_Truncation_Error__short_File_15.java | line=134 | data = 0;
CWE197_Numeric_Truncation_Error__short_File_15.java | line=136 | default:
CWE197_Numeric_Truncation_Error__short_File_15.java | line=138 | data = 2;
CWE197_Numeric_Truncation_Error__short_File_15.java | line=144 | IO.writeLine((byte)data);
```

**실제 트레이스**

```text
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=129, col=9 | switch(5)
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=129, col=17 | 5
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=134, col=13 | data
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=134, col=20 | 0
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=138, col=13 | data
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=138, col=20 | 2
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__short_File_15.java | line=144, col=13 | IO.writeLine((byte) data)
CWE197_Numeric_Truncation_Error__short_File_15.java | line=144, col=13 | IO
CWE197_Numeric_Truncation_Error__short_File_15.java | line=144, col=26 | (byte) data
```

**비교 결과**

- 추출 범위: 적절

### [5] CWE-197 / Testcase 327_flow2

- Java 파일명:
    - CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java
    - CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java

#### (1) Flow2 g2b

- Source: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java:110
- Sink: CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java:39

**예상 트레이스**

```text
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=110 | data = 2;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=112 | (new CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b()).goodG2BSink();
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=33 | public void goodG2BSink() throws Throwable
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=35 | int data = CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.data;
CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39 | IO.writeLine((byte)data);
```

**실제 트레이스**

```text
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.java | line=110, col=16 | 2
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=35, col=13 | data
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=35, col=20 | CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68a.data
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=13 | IO.writeLine((byte) data)
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=13 | IO
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=26 | (byte) data
CWE197_Numeric_Truncation_Error/s02/CWE197_Numeric_Truncation_Error__int_URLConnection_to_byte_68b.java | line=39, col=32 | data
```

**비교 결과**

- 추출 범위: 적절

### [6] CWE-134 / Testcase 605_flow1

- Java 파일명:
    - CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java

#### (1) Flow1 b2b

- Source: CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java:52
- Sink: CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java:124

**예상 트레이스**

```text
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=52 | data = readerBuffered.readLine();
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=121 | if (data != null)
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=124 | System.out.format(data);
```

**실제 트레이스**

```text
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=52 | readerBuffered.readLine()
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=52 | data = readerBuffered.readLine()
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=121 | data != null
CWE134_Uncontrolled_Format_String__listen_tcp_format_13.java | line=124 | System.out.format(data)
```

**비교 결과**

- 추출 범위: 적절

### [7] CWE-134 / Testcase 96_flow3

- Java 파일명:
    - CWE134_Uncontrolled_Format_String__File_format_42.java

#### (1) Flow3 g2b

- Source: CWE134_Uncontrolled_Format_String__File_format_42.java:120
- Sink: CWE134_Uncontrolled_Format_String__File_format_42.java:132

**예상 트레이스**

```text
CWE134_Uncontrolled_Format_String__File_format_42.java | line=115 | private String goodG2BSource() throws Throwable
CWE134_Uncontrolled_Format_String__File_format_42.java | line=120 | data = "foo";
CWE134_Uncontrolled_Format_String__File_format_42.java | line=122 | return data;
CWE134_Uncontrolled_Format_String__File_format_42.java | line=127 | String data = goodG2BSource();
CWE134_Uncontrolled_Format_String__File_format_42.java | line=129 | if (data != null)
CWE134_Uncontrolled_Format_String__File_format_42.java | line=132 | System.out.format(data);
```

**실제 트레이스**

```text
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=115, col=5 | this
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=115, col=13 | RET
java/juliet/testcases/CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=120, col=9 | data
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=120, col=9 | data = "foo"
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=120, col=16 | "foo"
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=122, col=9 | return data;
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=122, col=16 | data
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=125, col=5 | this
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=127, col=16 | data
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=127, col=23 | this.goodG2BSource()
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=127, col=23 | this
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=129, col=9 | if (data != null)
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=129, col=13 | data
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=129, col=13 | data != null
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=129, col=21 | null
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=132, col=13 | System.out
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=132, col=13 | <operator>.arrayInitializer
CWE134_Uncontrolled_Format_String/s01/CWE134_Uncontrolled_Format_String__File_format_42.java | line=132, col=31 | data
```

**비교 결과**

- 추출 범위: (미기재)

### [8] CWE-134 / Testcase 433_flow1

- Java 파일명:
    - CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java
    - CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b.java
    - CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c.java
    - CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java

#### (1) Flow1 b2b

- Source: CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java:53
- Sink: CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java:29

**예상 트레이스**

```text
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | line=53 | data = readerBuffered.readLine();
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | line=101 | (new CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b()).badSink(data);

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b.java | line=23 | public void badSink(String data) throws Throwable
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b.java | line=25 | (new CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c()).badSink(data);

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c.java | line=23 | public void badSink(String data) throws Throwable
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c.java | line=25 | (new CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d()).badSink(data);

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=23 | public void badSink(String data) throws Throwable
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=26 | if (data != null)
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=29 | System.out.printf(data);
```

**실제 트레이스**

```text
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | line=53 | readerBuffered.readLine()
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | line=53 | data = readerBuffered.readLine()
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53a.java | line=101 | this.badSink(data)

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b.java | line=23 | badSink(this, String data)
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53b.java | line=25 | this.badSink(data)

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c.java | line=23 | badSink(this, String data)
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53c.java | line=25 | this.badSink(data)

CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=23 | badSink(this, String data)
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=26 | data != null
CWE134_Uncontrolled_Format_String__connect_tcp_printf_53d.java | line=29 | System.out.printf(data)
```

**비교 결과**

- 추출 범위: (미기재)

### [9] CWE-134 / Testcase 33_flow2

- Java 파일명:
    - CWE134_Uncontrolled_Format_String__Environment_format_72a.java
    - CWE134_Uncontrolled_Format_String__Environment_format_72b.java

#### (1) Flow2 b2g

- Source: CWE134_Uncontrolled_Format_String__Environment_format_72a.java:67
- Sink: CWE134_Uncontrolled_Format_String__Environment_format_72b.java:57

**예상 트레이스**

```text
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=67 | data = System.getenv("ADD");
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=69 | Vector<String> dataVector = new Vector<String>(5);
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=70 | dataVector.add(0, data);
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=71 | dataVector.add(1, data);
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=72 | dataVector.add(2, data);
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=73 | (new CWE134_Uncontrolled_Format_String__Environment_format_72b()).goodB2GSink(dataVector);

CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=50 | public void goodB2GSink(Vector<String> dataVector) throws Throwable
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=52 | String data = dataVector.remove(2);
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=54 | if (data != null)
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57 | System.out.format("%s%n", data);
```

**실제 트레이스**

```text
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=67, col=9 | data
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=67, col=16 | System.getenv("ADD")
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=67, col=16 | System
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=67, col=30 | "ADD"
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=69, col=24 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=69, col=37 | new Vector<String>(5)
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=69, col=56 | 5
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=70, col=9 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=70, col=24 | 0
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=70, col=27 | data
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=71, col=9 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=71, col=24 | 1
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=71, col=27 | data
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=72, col=9 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=72, col=24 | 2
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=72, col=27 | data
CWE134_Uncontrolled_Format_String__Environment_format_72a.java | line=73, col=87 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=50, col=29 | Vector<String> dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=52, col=16 | data
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=52, col=23 | dataVector
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=52, col=23 | dataVector.remove(2)
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=52, col=41 | 2
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=54, col=9 | if (data != null)
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=54, col=13 | data
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=54, col=13 | data != null
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=54, col=21 | null
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57, col=13 | <operator>.arrayInitializer
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57, col=13 | System.out
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57, col=13 | System.out.format("%s%n", data)
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57, col=31 | "%s%n"
CWE134_Uncontrolled_Format_String__Environment_format_72b.java | line=57, col=39 | data
```

**비교 결과**

- 추출 범위: (미기재)

### [10] CWE-134 / Testcase 31_flow2

- Java 파일명:
    - CWE134_Uncontrolled_Format_String__Environment_format_68a.java
    - CWE134_Uncontrolled_Format_String__Environment_format_68b.java

#### (1) Flow2 b2g

- Source: CWE134_Uncontrolled_Format_String__Environment_format_68a.java:57
- Sink: CWE134_Uncontrolled_Format_String__Environment_format_68b.java:56

**예상 트레이스**

```text
CWE134_Uncontrolled_Format_String__Environment_format_68a.java | line=57 | data = System.getenv("ADD");
CWE134_Uncontrolled_Format_String__Environment_format_68a.java | line=59 | (new CWE134_Uncontrolled_Format_String__Environment_format_68b()).goodB2GSink();

CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=49 | public void goodB2GSink() throws Throwable
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=51 | String data = CWE134_Uncontrolled_Format_String__Environment_format_68a.data;
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=53 | if (data != null)
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56 | System.out.format("%s%n", data);
```

**실제 트레이스**

```text
CWE134_Uncontrolled_Format_String__Environment_format_68a.java | line=57, col=30 | "ADD"

CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=51, col=16 | data
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=51, col=23 | CWE134_Uncontrolled_Format_String__Environment_format_68a.data

CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=53, col=9 | if (data != null)
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=53, col=13 | data
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=53, col=13 | data != null
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=53, col=21 | null

CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56, col=13 | <operator>.arrayInitializer
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56, col=13 | System.out
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56, col=13 | System.out.format("%s%n", data)
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56, col=31 | "%s%n"
CWE134_Uncontrolled_Format_String__Environment_format_68b.java | line=56, col=39 | data
```

**비교 결과**

- 추출 범위: (미기재)

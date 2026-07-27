# 슬라이싱 결과 수동 검토 메모

## 검토 정보

- 검토자: 윤상권
- 검토일: 07-23
- 담당 CWE: CWE-129, CWE-190

## 검토 대상 요약

CWE 2개에서 testcase 5개씩 선택

| 번호  | CWE | Testcase index | 대표 Java 파일명                                                                             | Flow 유형                                 |
| ---:| ---:| --------------:| --------------------------------------------------------------------------------------- | --------------------------------------- |
| 1   | 129 | 915            | CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54* (a~e) | goodG2B                                 |
| 2   | 129 | 572            | CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java        | bad/goodB2G/goodG2B                     |
| 3   | 129 | 420            | CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java  | bad/goodB2G1/goodB2G2/goodG2B1/goodG2B2 |
| 4   | 129 | 2234           | CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java      | bad/goodB2G1/goodB2G2/goodG2B1/goodG2B2 |
| 5   | 129 | 357            | CWE129_Improper_Validation_of_Array_Index__File_array_write_no_check_51* (a~b)          | goodG2B                                 |
| 6   | 190 | 2299           | CWE190_Integer_Overflow__short_console_readLine_square_05.java                          | bad/goodG2B1/goodG2B2                   |
| 7   | 190 | 815            | CWE190_Integer_Overflow__int_URLConnection_multiply_01.java                             | goodG2B                                 |
| 8   | 190 | 2233           | CWE190_Integer_Overflow__short_console_readLine_add_13.java                             | bad/goodB2G1/goodB2G2/goodG2B1/goodG2B2 |
| 9   | 190 | 1719           | CWE190_Integer_Overflow__int_max_multiply_17.java                                       | bad/goodB2G/goodG2B                     |
| 10  | 190 | 903            | CWE190_Integer_Overflow__int_connect_tcp_add_15.java                                    | bad/goodB2G1/goodB2G2/goodG2B1/goodG2B2 |

## Testcase별 검토

### [1] CWE-129 / Testcase 915

- Java 파일명:
  - CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54* (a~e)
- 슬라이싱 결과 파일: cwe129.txt

#### (1) Flow goodG2B

- Source: CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54a.java:115 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54e.java:46 (5 CFG node(s))

**예상 트레이스**

```text
/* goodG2B() - use goodsource and badsink */
   private void goodG2B() throws Throwable
   {
       int data;

       /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
       data = 2;

       (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54b()).goodG2BSink(data );

    public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54c()).goodG2BSink(data );

    /* goodG2B() - use goodsource and badsink */
    public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54d()).goodG2BSink(data );

    /* goodG2B() - use goodsource and badsink */
    public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54e()).goodG2BSink(data );

    /* goodG2B() - use goodsource and badsink */
    public void goodG2BSink(int data ) throws Throwable
    {

        /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
        int array[] = { 0, 1, 2, 3, 4 };

        /* POTENTIAL FLAW: Attempt to write to array at location data, which may be outside the array bounds */
        array[data] = 42;
```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ] / 해결
- 근거: 사용 중인 Joern 4.0.575의 EngineConfig.maxCallDepth 기본값은 4 ->  reachableByFlows에 더 큰 EngineContext를 전달 

---

### [2] CWE-129 / Testcase 572

- Java 파일명:
  - CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java
- 슬라이싱 결과 파일: cwe129.txt

#### (1) Flow bad

- Source: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:40 (1 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:57 (5 CFG node(s))

**예상 트레이스**

```text
    public void bad() throws Throwable
    {
        int data;
        data = Integer.MIN_VALUE; /* Initialize data */
        try
        { 
        data = Integer.parseInt(stringNumber.trim());
        }
        for (int j = 0; j < 1; j++)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data < array.length, but don't verify that data > 0, so may be attempting to read out of the array bounds */
            if (data < array.length)
            {
                IO.writeLine(array[data]);
```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: source를 잘못 지정함 `{` source로 지정하고 있는 40번째 라인인 이 값이였음. 
  추가적으로 해당 source는 `{...}` 인 코드 뭉치로 보임. 그래서 주석 아랫줄이 `{` 임

---

#### (2) Flow goodB2G

- Source: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:101 (1 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:118 (9 CFG node(s))

**예상 트레이스**

```text
    public void bad() throws Throwable
    {
        int data;
        data = Integer.MIN_VALUE; /* Initialize data */
        String stringNumber = System.getProperty("user.home");
        try
        {
            data = Integer.parseInt(stringNumber.trim());
        }
        for (int j = 0; j < 1; j++)
       {
            int array[] = { 0, 1, 2, 3, 4 };
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: source를 잘못 지정함 `{` source로 지정하고 있는 101번째 라인인 이 값이였음. 
  추가적으로 해당 source는 `{...}` 인 코드 뭉치로 보임. 그래서 주석 아랫줄이 `{` 임



---

#### (3) Flow goodG2B

- Source: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:74 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java:81 (5 CFG node(s))

**예상 트레이스**

```text
    private void goodG2B() throws Throwable
    {
        int data;
        data = 2;
        for (int j = 0; j < 1; j++)
        {
            int array[] = { 0, 1, 2, 3, 4 };
            if (data < array.length)
            {
                IO.writeLine(array[data]);
```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=74, col=9 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=74, col=16 | 2
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=9 | for (int j = 0; j < 1; j++)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=18 | j
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=22 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=25 | j < 1
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=25 | j
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=29 | 1
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=76, col=32 | j
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=81, col=13 | if (data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=81, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__Property_array_read_check_max_17.java | line=81, col=24 | array.length
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 실제 취약점이 트리거 되는 부분은 `IO.writeLine(array[data]);` 과 같은 83번째 라인의 코드임. 그러나 위 트레이스에서는 `POTENTIAL FLOW` 이 주석이 `if (data < array.length)` 위 부분에 달려 있어 검증하는 부분에 달려있음 





### [3] CWE-129 / Testcase 420

- Java 파일명:
  - CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java
- 슬라이싱 결과 파일: cwe129.txt

#### (1) Flow bad

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:47 (5 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:93 (4 CFG node(s))

**예상 트레이스**

```text
String stringNumber = properties.getProperty("data");
if (stringNumber != null) // avoid NPD incidental warnings
{
    try
    {
        data = Integer.parseInt(stringNumber.trim());
    }
}
finally
{
    /* Close stream reading object */
    try
    {
        if (streamFileInput != null)
        {
            streamFileInput.close();
        }
    }
}
if (IO.STATIC_FINAL_FIVE==5)
{
    /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
    int array[] = { 0, 1, 2, 3, 4 };
    /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
    if (data >= 0)
    {
        IO.writeLine(array[data]);
```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=35, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=35, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=35, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=35, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=37, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=37, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=40, col=28 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=40, col=41 | new Properties()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=42, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=44, col=21 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=44, col=39 | new FileInputStream("../common/config.properties")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=44, col=59 | "../common/config.properties"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=45, col=21 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=45, col=37 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=47, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=47, col=43 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=47, col=43 | properties.getProperty("data")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=47, col=66 | "data"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=48, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=48, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=48, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=48, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=50, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=52, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=52, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=52, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=52, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=52, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=85, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=85, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=88, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=88, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=88, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=88, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=93, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=93, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=93, col=25 | 0

```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 여기서도 sink가 ` if (data >= 0)` 로 실제 취약점이 발생한다고 보기가 애매함. 또 추추적 과정에서 나오면 안되는 `data = 0` 이 부분이 아래와 같이 포함됨

```
else
{
    /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
     * but ensure data is inititialized before the Sink to avoid compiler errors */
    data = 0;
}

```



---

#### (2) Flow goodB2G1

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:186 (5 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:239 (9 CFG node(s))

**예상 트레이스**

```
private void goodB2G1() throws Throwable
{
    int data;
    if (IO.STATIC_FINAL_FIVE==5)
    {
        data = Integer.MIN_VALUE; /* Initialize data */
        {
            Properties properties = new Properties();
            FileInputStream streamFileInput = null;
            try
            {
                streamFileInput = new FileInputStream("../common/config.properties");
                properties.load(streamFileInput);
                /* POTENTIAL FLAW: Read data from a .properties file */
                String stringNumber = properties.getProperty("data");
                if (stringNumber != null) // avoid NPD incidental warnings
                {
                    try
                    {
                        data = Integer.parseInt(stringNumber.trim());
                    }
                }
            }
        }
    }

    if (IO.STATIC_FINAL_FIVE!=5)
    else
    {
        int array[] = { 0, 1, 2, 3, 4 };

        /* FIX: Fully verify data before reading from array at location data */
        if (data >= 0 && data < array.length)
        {
            IO.writeLine(array[data]);
```



**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=174, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=174, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=174, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=174, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=176, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=176, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=179, col=28 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=179, col=41 | new Properties()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=181, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=183, col=21 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=183, col=39 | new FileInputStream("../common/config.properties")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=183, col=59 | "../common/config.properties"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=184, col=21 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=184, col=37 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=186, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=186, col=43 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=186, col=43 | properties.getProperty("data")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=186, col=66 | "data"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=187, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=187, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=187, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=187, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=189, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=191, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=191, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=191, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=191, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=191, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=224, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=224, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=227, col=9 | if (IO.STATIC_FINAL_FIVE != 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=227, col=13 | IO.STATIC_FINAL_FIVE != 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=227, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=227, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=13 | if (data >= 0 && data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=17 | data >= 0 && data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=25 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=30 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=30 | data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=239, col=37 | array.length

```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 위 예시였던 것과 같음 `data = 0;`  / `else`  추출 안됨. 



---



#### (3) Flow goodB2G2

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:267 (5 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:313 (9 CFG node(s))

**예상 트레이스**

```
    private void goodB2G2() throws Throwable
    {
        int data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                Properties properties = new Properties();
                FileInputStream streamFileInput = null;
                try
                {
                    streamFileInput = new FileInputStream("../common/config.properties");
                    properties.load(streamFileInput);
                    /* POTENTIAL FLAW: Read data from a .properties file */
                    String stringNumber = properties.getProperty("data");
                    if (stringNumber != null) // avoid NPD incidental warnings
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }
            }
        }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            int array[] = { 0, 1, 2, 3, 4 };
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
            }
        }
    }
```



**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=257, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=257, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=260, col=28 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=260, col=41 | new Properties()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=262, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=21 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=39 | new FileInputStream("../common/config.properties")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=59 | "../common/config.properties"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=265, col=21 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=265, col=37 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=43 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=43 | properties.getProperty("data")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=66 | "data"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=270, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=305, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=305, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=13 | if (data >= 0 && data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data >= 0 && data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=25 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=30 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=30 | data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=37 | array.length

```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 위와 비슷한 이유 + 
```

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* FIX: Fully verify data before reading from array at location data */
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
            }
```

308 ~ 316라인의 내용중 `int array[] = { 0, 1, 2, 3, 4 };` 이 부분 라인이 추출이 되지 않았음. 취약점과 크게 관련이 있는지 애매함

#### (3) Flow goodB2G2

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:267 (5 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:313 (9 CFG node(s))

**예상 트레이스**
```
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=255, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=257, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=257, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=260, col=28 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=260, col=41 | new Properties()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=262, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=21 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=39 | new FileInputStream("../common/config.properties")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=264, col=59 | "../common/config.properties"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=265, col=21 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=265, col=37 | streamFileInput
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=43 | properties
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=43 | properties.getProperty("data")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=267, col=66 | "data"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=268, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=270, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=272, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=305, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=305, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=308, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=13 | if (data >= 0 && data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=17 | data >= 0 && data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=25 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=30 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=30 | data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=313, col=37 | array.length
```

**실제 트레이스**

```text
 private void goodB2G2() throws Throwable
    {
        int data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                Properties properties = new Properties();
                FileInputStream streamFileInput = null;
                try
                {
                    streamFileInput = new FileInputStream("../common/config.properties");
                    properties.load(streamFileInput);
                    /* POTENTIAL FLAW: Read data from a .properties file */
                    String stringNumber = properties.getProperty("data");
                    if (stringNumber != null) // avoid NPD incidental warnings
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }
            }
        }
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* FIX: Fully verify data before reading from array at location data */
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
            }
        }
    }
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 



#### (4) Flow goodG2B1

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:118 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:127 (4 CFG node(s))


**예상 트레이스**

```text
 private void goodG2B1() throws Throwable
    {
        int data;
        if (IO.STATIC_FINAL_FIVE!=5)
        else
        {

            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;

        }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
            if (data >= 0)
            {
                IO.writeLine(array[data]);
            }
        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=108, col=9 | if (IO.STATIC_FINAL_FIVE != 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=108, col=13 | IO.STATIC_FINAL_FIVE != 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=108, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=108, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=112, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=112, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=118, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=118, col=20 | 2
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=122, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=122, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=122, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=122, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=127, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=127, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=127, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=127, col=25 | 0

```

**비교 결과**

- 추출 범위: [ 적절 / 과도 / 부족 ]
- 근거: dead code가 추출 됨

```
        if (IO.STATIC_FINAL_FIVE!=5)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run
             * but ensure data is inititialized before the Sink to avoid compiler errors */
            data = 0;
        }
``` 

112 번이 죽은 코드인데 추출됨. 또 array[] 배열은 추출이 안되는데 이는 고려해볼 만한 이슈 인것 같음 


#### (5) Flow goodG2B2

- Source: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:145 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java:159 (4 CFG node(s))

**예상 트레이스**

```text
    private void goodG2B2() throws Throwable
    {
        int data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
            if (data >= 0)
            {
                IO.writeLine(array[data]);
            }
        }
    }

```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=142, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=142, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=142, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=142, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=145, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=145, col=20 | 2
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=151, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=151, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=154, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=154, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=154, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=154, col=35 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=159, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=159, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s04/CWE129_Improper_Validation_of_Array_Index__PropertiesFile_array_read_check_min_13.java | line=159, col=25 | 0

```

**비교 결과**

- 추출 범위: [ 적절 / 과도 / 부족 ]
- 근거: 여기도 deadcode와 array는 추적되지 않음. 




### [4] CWE-129 / Testcase 2234

- Java 파일명:
    - CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java
- 슬라이싱 결과 파일: cwe129.txt

#### (1) Flow bad

- Source: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:53 (4 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:136 (4 CFG node(s))

**예상 트레이스**

```text
    public void bad() throws Throwable
    {
        int data;
        if (IO.staticFive==5)
        {
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                ServerSocket listener = null;
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                /* Read data using a listening tcp connection */
                try
                {
                    listener = new ServerSocket(39543);
                    socket = listener.accept();
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using a listening tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) // avoid NPD incidental warnings
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }
            }
        }

        if (IO.staticFive==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
            if (data >= 0)
            {
                IO.writeLine(array[data]);
            }
        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=36, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=36, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=36, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=36, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=38, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=38, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=45, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=47, col=21 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=47, col=32 | new ServerSocket(39543)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=47, col=49 | 39543
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=48, col=21 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=48, col=30 | listener.accept()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=48, col=30 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=50, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=50, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=50, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=50, col=63 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=50, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=51, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=51, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=51, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=53, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=53, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=53, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=54, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=54, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=54, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=54, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=56, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=58, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=58, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=58, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=58, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=58, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=128, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=128, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=131, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=131, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=131, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=131, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=136, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=136, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=136, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=136, col=25 | 0

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 잘 뽑혔지만 deadcode도 뽑힘. 


#### (2) Flow goodG2B

- Source: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:234 (4 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:324 (9 CFG node(s))

**예상 트레이스**

```text
 private void goodB2G1() throws Throwable
    {
        int data;
        if (IO.staticFive==5)
        {
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                ServerSocket listener = null;
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                /* Read data using a listening tcp connection */
                try
                {
                    listener = new ServerSocket(39543);
                    socket = listener.accept();
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using a listening tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) // avoid NPD incidental warnings
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }

        if (IO.staticFive!=5)
        else
        {

            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };

            /* FIX: Fully verify data before reading from array at location data */
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
            }
        }
    }

```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=217, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=217, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=217, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=217, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=219, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=219, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=226, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=228, col=21 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=228, col=32 | new ServerSocket(39543)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=228, col=49 | 39543
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=229, col=21 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=229, col=30 | listener.accept()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=229, col=30 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=231, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=231, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=231, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=231, col=63 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=231, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=232, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=232, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=232, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=234, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=234, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=234, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=235, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=235, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=235, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=235, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=237, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=239, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=239, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=239, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=239, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=239, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=309, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=309, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=312, col=9 | if (IO.staticFive != 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=312, col=13 | IO.staticFive != 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=312, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=312, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=13 | if (data >= 0 && data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=17 | data >= 0 && data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=25 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=30 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=30 | data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=324, col=37 | array.length

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 대체로 잘 뽑힘 그러나 deadcode가 포함됨


#### (3) Flow goodG2B

- Source: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:357 (4 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:440 (9 CFG node(s))

**예상 트레이스**

```text

    private void goodB2G2() throws Throwable
    {
        int data;
        if (IO.staticFive==5)
        {
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                ServerSocket listener = null;
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                /* Read data using a listening tcp connection */
                try
                {
                    listener = new ServerSocket(39543);
                    socket = listener.accept();
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using a listening tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) // avoid NPD incidental warnings
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }

                }
 
            }

        if (IO.staticFive==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* FIX: Fully verify data before reading from array at location data */
            if (data >= 0 && data < array.length)
            {
                IO.writeLine(array[data]);
            }

        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=340, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=340, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=340, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=340, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=342, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=342, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=349, col=17 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=351, col=21 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=351, col=32 | new ServerSocket(39543)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=351, col=49 | 39543
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=352, col=21 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=352, col=30 | listener.accept()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=352, col=30 | listener
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=354, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=354, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=354, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=354, col=63 | socket
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=354, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=355, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=355, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=355, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=357, col=28 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=357, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=357, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=358, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=358, col=25 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=358, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=358, col=41 | null
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=360, col=25 | try
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=362, col=29 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=362, col=36 | Integer
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=362, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=362, col=53 | stringNumber
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=362, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=432, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=432, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=435, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=435, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=435, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=435, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=13 | if (data >= 0 && data < array.length)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=17 | data >= 0 && data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=25 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=30 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=30 | data < array.length
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=440, col=37 | array.length

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 적절하게 뽑혔으나 deadcode가 뽑힘

#### (4) Flow goodG2B1

- Source: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:161 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:170 (4 CFG node(s))


**예상 트레이스**

```text

    private void goodG2B1() throws Throwable
    {
        int data;
        if (IO.staticFive!=5)
        else
        {

            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;

        }

        if (IO.staticFive==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
            if (data >= 0)
            {
                IO.writeLine(array[data]);
            }

        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=151, col=9 | if (IO.staticFive != 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=151, col=13 | IO.staticFive != 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=151, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=151, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=155, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=155, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=161, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=161, col=20 | 2
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=165, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=165, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=165, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=165, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=170, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=170, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=170, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=170, col=25 | 0
.
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 적절하나 deadcode가 같이 뽑힘. 

#### (5) Flow  goodG2B2

- Source: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:188 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java:202 (4 CFG node(s))

**예상 트레이스**

```text
    private void goodG2B2() throws Throwable
    {
        int data;
        if (IO.staticFive==5)
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }

        if (IO.staticFive==5)
        {
            /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
            int array[] = { 0, 1, 2, 3, 4 };
            /* POTENTIAL FLAW: Verify that data >= 0, but don't verify that data < array.length, so may be attempting to read out of the array bounds */
            if (data >= 0)
            {
                IO.writeLine(array[data]);
            }
        }
    }



```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=185, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=185, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=185, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=185, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=188, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=188, col=20 | 2
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=194, col=13 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=194, col=20 | 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=197, col=9 | if (IO.staticFive == 5)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=197, col=13 | IO.staticFive == 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=197, col=13 | IO.staticFive
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=197, col=28 | 5
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=202, col=13 | if (data >= 0)
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=202, col=17 | data
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=202, col=17 | data >= 0
src/main/java/juliet/testcases/CWE129_Improper_Validation_of_Array_Index/s03/CWE129_Improper_Validation_of_Array_Index__listen_tcp_array_read_check_min_14.java | line=202, col=25 | 0

```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 구문 if는 뽑히는데, else는 안뽑힘. deadcode도 뽑힘


### [5] CWE-129 / Testcase 357

- Java 파일명:
    - CWE129_Improper_Validation_of_Array_Index__File_array_write_no_check_51* (a e) 
- 슬라이싱 결과 파일: cwe129.txt

#### (1) Flow goodG2B

- Source: CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54a.java:115 (3 CFG node(s))
- Sink: CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54e.java:46 (5 CFG node(s))

**예상 트레이스**

```text

private void goodG2B() throws Throwable
    {
        int data;

        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        data = 2;

        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54b()).goodG2BSink(data );
 public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54c()).goodG2BSink(data );
    public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54d()).goodG2BSink(data );
    public void goodG2BSink(int data ) throws Throwable
    {
        (new CWE129_Improper_Validation_of_Array_Index__URLConnection_array_write_no_check_54e()).goodG2BSink(data );
  public void goodG2BSink(int data ) throws Throwable
    {

        /* Need to ensure that the array is of size > 3  and < 101 due to the GoodSource and the large_fixed BadSource */
        int array[] = { 0, 1, 2, 3, 4 };

        /* POTENTIAL FLAW: Attempt to write to array at location data, which may be outside the array bounds */
        array[data] = 42;

```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 추적 실패함



---

### [6] CWE-190 / Testcase 2299

- Java 파일명:
    - CWE190_Integer_Overflow__short_console_readLine_square_05.java     
- 슬라이싱 결과 파일: cwe190.txt

#### (1) Flow bad

- Source: CWE190_Integer_Overflow__short_console_readLine_square_05.java:46 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_square_05.java:106 (7 CFG node(s))
**예상 트레이스**

```text
public void bad() throws Throwable
    {
        short data;
        if (privateTrue)
        {
            /* init data */
            data = -1;
            /* POTENTIAL FLAW: Read data from console with readLine*/
            BufferedReader readerBuffered = null;
            InputStreamReader readerInputStream = null;
            try
            {
                readerInputStream = new InputStreamReader(System.in, "UTF-8");
                readerBuffered = new BufferedReader(readerInputStream);
                String stringNumber = readerBuffered.readLine();
                if (stringNumber != null)
                {
                    data = Short.parseShort(stringNumber.trim());
                }
            }
        }
        if (privateTrue)
        {
            /* POTENTIAL FLAW: if (data*data) > Short.MAX_VALUE, this will overflow */
            short result = (short)(data * data);
            IO.writeLine("result: " + result);
        }
    }

```

**실제 트레이스**

```text

=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 해당 취약점이 기존과 다른 오류로 인해 나오지 않았다. 

먼저, 기존에 트레이스가 나오지 않았던 케이스는 
1. XML에 기록된 Source 또는 Sink 라인 번호가 실제 취약 연산의 위치와 일치하지 않은 경우
2. 여러 파일에 걸친 호출에서 추상 클래스나 중간 전달 파일이 CPG에 포함되지 않아 DDG가 연결되지 않은 경우

이 두 케이스였다. 

이번 케이스는 추론해보기로는 source와 sink가 맞지 않아 생긴 문제로 보인다. 

먼저 sink로 찍은 부분을 보면 
`short result = (short)(data * data);` data  부분으로 overflow sink 임을 알 수 있다. 
그러나 source를 보면 
` BufferedReader readerBuffered = null;` readerBuffered를 초기화 하는 부분이 되어 있음을 알 수 있다. 
이 코드는 외부 입력을 읽는 연산이 아니라 `BufferedReader` 변수를 `null`로 초기화하는 문장이다. 
따라서 이 노드에서 `data * data`까지 이어지는 데이터 흐름이 찾기가 어려워 보인다, 
그러므로 `reachableByFlows`가 경로를 찾지 못한 것이 자연스러운 결과로 보인다.

실제적으로 `stringNumber = readerBuffered.readLine();` 이런 부분이나, `data = Short.parseShort(stringNumber.trim());` 이런 부분이 source로 되어야 되지 않나싶다. 

#### (2) Flow goodG2B1

- Source: CWE190_Integer_Overflow__short_console_readLine_square_05.java:125 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_square_05.java:132 (7 CFG node(s))

**예상 트레이스**

```text

  private void goodG2B1() throws Throwable
    {
        short data;
        if (privateFalse)
        else
        {

            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;

        }

        if (privateTrue)
        {
            /* POTENTIAL FLAW: if (data*data) > Short.MAX_VALUE, this will overflow */
            short result = (short)(data * data);
        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=115, col=9 | if (this.privateFalse)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=115, col=13 | this.privateFalse
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=119, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=119, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=125, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=125, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=129, col=9 | if (this.privateTrue)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=129, col=13 | this.privateTrue
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=132, col=19 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=132, col=28 | (short) (data * data)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=132, col=36 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=132, col=36 | data * data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=132, col=43 | data


```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: `else` 구문 미 추출과 deadcode 추출

#### (3) Flow goodG2B2

- Source: CWE190_Integer_Overflow__short_console_readLine_square_05.java:144 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_square_05.java:156 (7 CFG node(s))

**예상 트레이스**

```text
  private void goodG2B2() throws Throwable
    {
        short data;
        if (privateTrue)
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }

        if (privateTrue)
        {
            /* POTENTIAL FLAW: if (data*data) > Short.MAX_VALUE, this will overflow */
            short result = (short)(data * data);        }
    }


```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=141, col=9 | if (this.privateTrue)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=141, col=13 | this.privateTrue
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=144, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=144, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=150, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=150, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=153, col=9 | if (this.privateTrue)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=153, col=13 | this.privateTrue
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=156, col=19 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=156, col=28 | (short) (data * data)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=156, col=36 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=156, col=36 | data * data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_square_05.java | line=156, col=43 | data

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: deadcode가 추출됨. 


### [7] CWE-190 / Testcase 815

- Java 파일명:
    - CWE190_Integer_Overflow__int_URLConnection_multiply_01.java  
- 슬라이싱 결과 파일: cwe190.txt

#### (1) Flow goodG2B

- Source: CWE190_Integer_Overflow__int_URLConnection_multiply_01.java:121 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_URLConnection_multiply_01.java:126 (7 CFG node(s))

**예상 트레이스**

```text

   private void goodG2B() throws Throwable
    {
        int data;

        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        data = 2;

        if(data > 0) /* ensure we won't have an underflow */
        {
            /* POTENTIAL FLAW: if (data*2) > Integer.MAX_VALUE, this will overflow */
            int result = (int)(data * 2);
        }

    }


```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=121, col=9 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=121, col=16 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=123, col=9 | if (data > 0)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=123, col=12 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=123, col=12 | data > 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=123, col=19 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=126, col=17 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=126, col=17 | int result = (int) (data * 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=126, col=26 | (int) (data * 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=126, col=32 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__int_URLConnection_multiply_01.java | line=126, col=39 | 2
```

**비교 결과**

- 추출 범위: [ 적절]
- 근거: 

### [8] CWE-190 / Testcase 2233

- Java 파일명:
    - CWE190_Integer_Overflow__short_console_readLine_add_13.java 
- 슬라이싱 결과 파일: cwe190.txt

#### (1) Flow bad

- Source: CWE190_Integer_Overflow__short_console_readLine_add_13.java:39 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_add_13.java:99 (7 CFG node(s))

**예상 트레이스**

```text
    public void bad() throws Throwable
    {
        short data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* init data */
            data = -1;
            /* POTENTIAL FLAW: Read data from console with readLine*/
            BufferedReader readerBuffered = null;
            InputStreamReader readerInputStream = null;
            try
            {
                readerInputStream = new InputStreamReader(System.in, "UTF-8");
                readerBuffered = new BufferedReader(readerInputStream);
                String stringNumber = readerBuffered.readLine();
                if (stringNumber != null)
                {
                    data = Short.parseShort(stringNumber.trim());
                }
            }
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* POTENTIAL FLAW: if data == Short.MAX_VALUE, this will overflow */
            short result = (short)(data + 1);
        }
    }

```

**실제 트레이스**

```text
No data-flow path found.

```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 이전에 설명했던 것과 같은 case로 확인됨. source 부분이 초기화 하는 부분임. 

#### (2) Flow goodG2B

- Source: CWE190_Integer_Overflow__short_console_readLine_add_13.java:163 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_add_13.java:229 (6 CFG node(s))

**예상 트레이스**

```text
   private void goodB2G1() throws Throwable
    {
        short data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* init data */
            data = -1;
            /* POTENTIAL FLAW: Read data from console with readLine*/
            BufferedReader readerBuffered = null;
            InputStreamReader readerInputStream = null;
            try
            {
                readerInputStream = new InputStreamReader(System.in, "UTF-8");
                readerBuffered = new BufferedReader(readerInputStream);
                String stringNumber = readerBuffered.readLine();
                if (stringNumber != null)
                {
                    data = Short.parseShort(stringNumber.trim());
                }
            }


        if (IO.STATIC_FINAL_FIVE!=5)

        else
        {

            /* FIX: Add a check to prevent an overflow from occurring */
            if (data < Short.MAX_VALUE)

        }
    }

```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 위와 같은 이유.


#### (3) Flow goodB2G2

- Source: CWE190_Integer_Overflow__short_console_readLine_add_13.java:251 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_add_13.java:311 (6 CFG node(s))

**예상 트레이스**

```text
  private void goodB2G2() throws Throwable
    {
        short data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* init data */
            data = -1;
            /* POTENTIAL FLAW: Read data from console with readLine*/
            BufferedReader readerBuffered = null;
            InputStreamReader readerInputStream = null;
            try
            {
                readerInputStream = new InputStreamReader(System.in, "UTF-8");
                readerBuffered = new BufferedReader(readerInputStream);
                String stringNumber = readerBuffered.readLine();
                if (stringNumber != null)
                {
                    data = Short.parseShort(stringNumber.trim());
                }
            }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* FIX: Add a check to prevent an overflow from occurring */
            if (data < Short.MAX_VALUE)
        }
    }

```

**실제 트레이스**

```text
=== Source-to-Sink Trace ===
No data-flow path found.
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 위와 같은 이유. 

#### (4) Flow goodG2B1

- Source: CWE190_Integer_Overflow__short_console_readLine_add_13.java:118 (3 CFG node(s))
- Sink:  CWE190_Integer_Overflow__short_console_readLine_add_13.java:125 (7 CFG node(s))

**예상 트레이스**

```text
  private void goodG2B1() throws Throwable
    {
        short data;
        if (IO.STATIC_FINAL_FIVE!=5)
 
        else
        {

            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;

        }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* POTENTIAL FLAW: if data == Short.MAX_VALUE, this will overflow */
            short result = (short)(data + 1);
        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=108, col=9 | if (IO.STATIC_FINAL_FIVE != 5)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=108, col=13 | IO.STATIC_FINAL_FIVE != 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=108, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=108, col=35 | 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=112, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=112, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=118, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=118, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=122, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=122, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=122, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=122, col=35 | 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=125, col=19 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=125, col=19 | short result = (short) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=125, col=28 | (short) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=125, col=36 | data + 1
```

**비교 결과**

- 추출 범위: [ 부족 ]
- 근거: 전반적으로 잘 뽑혔으나 `else` 구문은 추출되지 않았음. deadcode도 추출됨


#### (1) Flow goodG2B2

- Source: CWE190_Integer_Overflow__short_console_readLine_add_13.java:137 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__short_console_readLine_add_13.java:149 (7 CFG node(s))

**예상 트레이스**

```text

    private void goodG2B2() throws Throwable
    {
        short data;
        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
        }

        if (IO.STATIC_FINAL_FIVE==5)
        {
            /* POTENTIAL FLAW: if data == Short.MAX_VALUE, this will overflow */
            short result = (short)(data + 1);
        }
    }

```

**실제 트레이스**

```text
ㄴrc/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=134, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=134, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=134, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=134, col=35 | 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=137, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=137, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=143, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=143, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=146, col=9 | if (IO.STATIC_FINAL_FIVE == 5)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=146, col=13 | IO.STATIC_FINAL_FIVE == 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=146, col=13 | IO.STATIC_FINAL_FIVE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=146, col=35 | 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=149, col=19 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=149, col=28 | (short) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s04/CWE190_Integer_Overflow__short_console_readLine_add_13.java | line=149, col=36 | data
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: deadcode가 추출됨. 


### [9] CWE-190 / Testcase 1719

- Java 파일명:
    - CWE190_Integer_Overflow__int_max_multiply_17.java  
- 슬라이싱 결과 파일: cwe190.txt

#### (1) Flow bad

- Source: CWE190_Integer_Overflow__int_max_multiply_17.java:35 (5 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_max_multiply_17.java:42 (7 CFG node(s))

**예상 트레이스**

```text
    public void bad() throws Throwable
    {
        int data;

        /* POTENTIAL FLAW: Use the maximum value for this type */
        data = Integer.MAX_VALUE;

        for (int j = 0; j < 1; j++)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* POTENTIAL FLAW: if (data*2) > Integer.MAX_VALUE, this will overflow */
                int result = (int)(data * 2);
            }
        }
    }


```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=35, col=9 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=35, col=16 | Integer.MAX_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=9 | for (int j = 0; j < 1; j++)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=18 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=22 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=25 | j < 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=25 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=29 | 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=37, col=32 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=39, col=13 | if (data > 0)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=39, col=16 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=39, col=16 | data > 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=39, col=23 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=42, col=21 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=42, col=30 | (int) (data * 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=42, col=36 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=42, col=36 | data * 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=42, col=43 | 2
```

**비교 결과**

- 추출 범위: [ 적절  ]
- 근거: 

#### (2) Flow goodB2G

- Source: CWE190_Integer_Overflow__int_max_multiply_17.java:73 (5 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_max_multiply_17.java:80 (8 CFG node(s))

**예상 트레이스**

```text

   private void goodB2G() throws Throwable
    {
        int data;

        /* POTENTIAL FLAW: Use the maximum value for this type */
        data = Integer.MAX_VALUE;

        for (int k = 0; k < 1; k++)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* FIX: Add a check to prevent an overflow from occurring */
                if (data < (Integer.MAX_VALUE/2))
                {
                    int result = (int)(data * 2);
                }

            }
        }
    }


```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=73, col=9 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=73, col=16 | Integer.MAX_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=9 | for (int k = 0; k < 1; k++)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=18 | k
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=22 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=25 | k < 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=25 | k
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=29 | 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=75, col=32 | k
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=77, col=13 | if (data > 0)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=77, col=16 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=77, col=16 | data > 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=77, col=23 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=17 | if (data < (Integer.MAX_VALUE / 2))
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=21 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=21 | data < (Integer.MAX_VALUE / 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=29 | Integer.MAX_VALUE / 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=29 | Integer.MAX_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=80, col=47 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=82, col=40 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=82, col=47 | 2

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 
적절하게 뽑힘 다만 한가지 특이사항으로는 
```
/* FIX: Add a check to prevent an overflow from occurring */
if (data < (Integer.MAX_VALUE/2))`
```
이 코드가 sink로 지정되어 었는데 최종 sink는 `  int result = (int)(data * 2);` 이 코드까지 슬라이싱 되어있음. 


#### (3) Flow goodG2B

- Source: CWE190_Integer_Overflow__int_max_multiply_17.java:54 (3 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_max_multiply_17.java:61 (7 CFG node(s))

**예상 트레이스**

```text

    private void goodG2B() throws Throwable
    {
        int data;

        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        data = 2;

        for (int j = 0; j < 1; j++)
        {
            if(data > 0) /* ensure we won't have an underflow */
            {
                /* POTENTIAL FLAW: if (data*2) > Integer.MAX_VALUE, this will overflow */
                int result = (int)(data * 2);
            }
        }
    }

```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=54, col=9 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=54, col=16 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=9 | for (int j = 0; j < 1; j++)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=18 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=22 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=25 | j < 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=25 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=29 | 1
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=56, col=32 | j
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=58, col=13 | if (data > 0)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=58, col=16 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=58, col=16 | data > 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=58, col=23 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=61, col=21 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=61, col=21 | int result = (int) (data * 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=61, col=30 | (int) (data * 2)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=61, col=36 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s03/CWE190_Integer_Overflow__int_max_multiply_17.java | line=61, col=43 | 2
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 


### [10] CWE-190 / Testcase 903

- Java 파일명:
    - CWE190_Integer_Overflow__int_connect_tcp_add_15.java   
- 슬라이싱 결과 파일: cwe190.txt

#### (1) Flow bad

- Source: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:53 (4 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:123 (8 CFG node(s))

**예상 트레이스**

```text

    public void bad() throws Throwable
    {
        int data;

        switch (6)
        {
        case 6:
            data = Integer.MIN_VALUE; /* Initialize data */
            {
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                try
                {
                    /* Read data using an outbound tcp connection */
                    socket = new Socket("host.example.org", 39544);
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using an outbound tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) /* avoid NPD incidental warnings */
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }

        switch (7)
        {
        case 7:
            /* POTENTIAL FLAW: if data == Integer.MAX_VALUE, this will overflow */
            int result = (int)(data + 1);

        }
    }


```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=36, col=9 | switch(6)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=36, col=17 | 6
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=39, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=39, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=45, col=17 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=48, col=21 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=48, col=30 | new Socket("host.example.org", 39544)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=48, col=41 | "host.example.org"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=48, col=61 | 39544
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=50, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=50, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=50, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=50, col=63 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=50, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=51, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=51, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=51, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=53, col=28 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=53, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=53, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=54, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=54, col=25 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=54, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=54, col=41 | null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=56, col=25 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=58, col=29 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=58, col=36 | Integer
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=58, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=58, col=53 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=58, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=115, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=115, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=119, col=9 | switch(7)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=119, col=17 | 7
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=123, col=17 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=123, col=17 | int result = (int) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=123, col=26 | (int) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=123, col=32 | data + 1

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 


#### (2) Flow goodB2G1

- Source: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:219 (4 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:293 (7 CFG node(s))

**예상 트레이스**

```text
    private void goodB2G1() throws Throwable
    {
        int data;

        switch (6)
        {
        case 6:
            data = Integer.MIN_VALUE; /* Initialize data */
            /* Read data using an outbound tcp connection */
            {
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                try
                {
                    /* Read data using an outbound tcp connection */
                    socket = new Socket("host.example.org", 39544);
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using an outbound tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) /* avoid NPD incidental warnings */
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }
            }
        }

        switch (8)
        {
        default:
            /* FIX: Add a check to prevent an overflow from occurring */
            if (data < Integer.MAX_VALUE)
            {
                int result = (int)(data + 1);
            }
        }
    }

```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=202, col=9 | switch(6)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=202, col=17 | 6
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=205, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=205, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=211, col=17 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=214, col=21 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=214, col=30 | new Socket("host.example.org", 39544)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=214, col=41 | "host.example.org"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=214, col=61 | 39544
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=216, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=216, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=216, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=216, col=63 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=216, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=217, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=217, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=217, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=219, col=28 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=219, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=219, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=220, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=220, col=25 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=220, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=220, col=41 | null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=222, col=25 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=224, col=29 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=224, col=36 | Integer
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=224, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=224, col=53 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=224, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=281, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=281, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=285, col=9 | switch(8)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=285, col=17 | 8
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=293, col=13 | if (data < Integer.MAX_VALUE)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=293, col=17 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=293, col=17 | data < Integer.MAX_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=293, col=24 | Integer
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=293, col=24 | Integer.MAX_VALUE
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거:

#### (3) Flow goodB2G2

- Source: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:328 (4 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:398 (7 CFG node(s))

**예상 트레이스**

```text
   private void goodB2G2() throws Throwable
    {
        int data;

        switch (6)
        {
        case 6:
            data = Integer.MIN_VALUE; /* Initialize data */
            /* Read data using an outbound tcp connection */
            {
                Socket socket = null;
                BufferedReader readerBuffered = null;
                InputStreamReader readerInputStream = null;
                try
                {
                    /* Read data using an outbound tcp connection */
                    socket = new Socket("host.example.org", 39544);
                    /* read input from socket */
                    readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
                    readerBuffered = new BufferedReader(readerInputStream);
                    /* POTENTIAL FLAW: Read data using an outbound tcp connection */
                    String stringNumber = readerBuffered.readLine();
                    if (stringNumber != null) /* avoid NPD incidental warnings */
                    {
                        try
                        {
                            data = Integer.parseInt(stringNumber.trim());
                        }
                    }
                }
            }
            break;
        }

        switch (7)
        {
        case 7:
            /* FIX: Add a check to prevent an overflow from occurring */
            if (data < Integer.MAX_VALUE)
            {
                int result = (int)(data + 1);
        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=311, col=9 | switch(6)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=311, col=17 | 6
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=314, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=314, col=20 | Integer.MIN_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=320, col=17 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=323, col=21 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=323, col=30 | new Socket("host.example.org", 39544)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=323, col=41 | "host.example.org"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=323, col=61 | 39544
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=325, col=21 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=325, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=325, col=63 | socket.getInputStream()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=325, col=63 | socket
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=325, col=88 | "UTF-8"
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=326, col=21 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=326, col=38 | new BufferedReader(readerInputStream)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=326, col=57 | readerInputStream
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=328, col=28 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=328, col=43 | readerBuffered
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=328, col=43 | readerBuffered.readLine()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=329, col=21 | if (stringNumber != null)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=329, col=25 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=329, col=25 | stringNumber != null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=329, col=41 | null
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=331, col=25 | try
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=333, col=29 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=333, col=36 | Integer
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=333, col=36 | Integer.parseInt(stringNumber.trim())
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=333, col=53 | stringNumber
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=333, col=53 | stringNumber.trim()
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=390, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=390, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=394, col=9 | switch(7)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=394, col=17 | 7
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=398, col=13 | if (data < Integer.MAX_VALUE)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=398, col=17 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=398, col=17 | data < Integer.MAX_VALUE
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=398, col=24 | Integer
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=398, col=24 | Integer.MAX_VALUE
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 전반적으로 잘 뽑힘 그러나 deadcode도 포함됨. 구문만 있는 요소들이 잘 안뽑힘.

#### (4) Flow goodG2B1

- Source: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:147 (4 CFG node(s))
- Sink: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:155 (8 CFG node(s))

**예상 트레이스**

```text

  private void goodG2B1() throws Throwable
    {
        int data;

        switch (5)
        {
        case 6:
        default:
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
            break;
        }

        switch (7)
        {
        case 7:
            /* POTENTIAL FLAW: if data == Integer.MAX_VALUE, this will overflow */
            int result = (int)(data + 1);

        }
    }

```

**실제 트레이스**

```text

src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=138, col=9 | switch(5)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=138, col=17 | 5
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=143, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=143, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=147, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=147, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=151, col=9 | switch(7)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=151, col=17 | 7
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=155, col=17 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=155, col=17 | int result = (int) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=155, col=26 | (int) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=155, col=32 | data + 1

```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 적절하나 dead code가 뽑힘.

#### (1) Flow goodG2B

- Source: CWE190_Integer_Overflow__int_connect_tcp_add_15.java:174 (4 CFG node(s))
- Sink:  CWE190_Integer_Overflow__int_connect_tcp_add_15.java:187 (8 CFG node(s))

**예상 트레이스**

```text

   private void goodG2B2() throws Throwable
    {
        int data;

        switch (6)
        {
        case 6:
            /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
            data = 2;
            break;
        }

        switch (7)
        {
        case 7:
            /* POTENTIAL FLAW: if data == Integer.MAX_VALUE, this will overflow */
            int result = (int)(data + 1);
        }
    }

```

**실제 트레이스**

```text
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=170, col=9 | switch(6)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=170, col=17 | 6
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=174, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=174, col=20 | 2
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=179, col=13 | data
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=179, col=20 | 0
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=183, col=9 | switch(7)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=183, col=17 | 7
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=187, col=17 | result
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=187, col=26 | (int) (data + 1)
src/main/java/juliet/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_connect_tcp_add_15.java | line=187, col=32 | data
```

**비교 결과**

- 추출 범위: [ 적절 ]
- 근거: 적절하나 deadcode가 뽑힘


# 문제사항 요약 

- Source와 Sink가 정확하게 지정된 단순 흐름에서는 취약점 관련 데이터 및 제어 흐름이 대체로 적절하게 추출됨
- 반면 일부 케이스에서는 Source·Sink 라인 오류, 메서드 호출 깊이 제한, 경로 비민감 분석, 구문적 문맥 누락 등의 문제가 발생함

추출 실패 또는 부정확한 결과의 상당수는 다음 세 부분을 원인으로 꼽아 볼 수 있음

1. XML에 기록된 Source, Sink 위치가 실제 취약 연산과 일치하지 않음 
2. 여러 파일(a~e)이나 깊은 메서드 호출을 포함하는 흐름의 분석 설정 부족 
3. Source to sink 경로를 찾은 뒤 Sink 기준으로 DDG를 확장하면서 실행 불가능한 분기까지 포함되는 문제 


## 1. XML source/sink 라인과 실제 취약 연산의 불일치. 


일부 테스트케이스에서 XML에 기록된 source, sink 라인이 실제 외부 입력이나 취약 연산이 아닌 위치를 가리킴 

- 코드 블록의 시작 기호인 `{`
- 지역 변수 초기화 `BufferedReader readerBuffered = null` 와 같은 코드가 source로 지정됨
- 취약 연산 이전의 검증 조건문에 `sink`가 지정됨 
    예를 들어 Out of index의 실제 배열 접근이 아닌 if (data >= 0) 조건 등.

대표사례 
    CWE-129 / Testcase 572
    CWE-190 / Testcase 2299
    CWE-129 배열 접근 테스트

추가적으로 Sink 라인의 의미가 테스트 마다 일관되지 않은 것을 확인함.
예를 들어 동일 취약점에서 다음과 같은 연산이 sink로 지정됨
`int result = data * 2;`

그러나 goodsink에서는 다음과 같은 검증 조건이 추가되었고 해당 조건이 sink로 지정되어 있음
`if (data < Integer.MAX_VALUE / 2)`

이때 경우에 따라서 조금 다른 경향이 있지만 보통 지정한 sink까지만 슬라이싱 되어 있고
이후 등장하는 연산이 누락되는 케이스가 확인됨 `int result = data * 2;`

## 2. 여러 파일 및 깊은 호출 체인의 탐색 제한

CWE-129 Testcase 915처럼 Source에서 Sink까지 여러 Java 파일을 순차적으로 거치는 경우 기본 설정에서 경로가 나오지 않았음. 
```
54a
→ 54b
→ 54c
→ 54d
→ 54e
```

이는 Joern 4.0.575의 기본 `EngineConfig.maxCallDepth`가 4이기 때문에, 호출 단계가 이를 초과하면 마지막 Sink까지 도달하지 못한 것으로 보임 
`maxCallDepth` 변수를 하나 두어서 적절히 값을 설정하면 해결될 문제로 확인됨

## 3. 실행되지 않는 분기와 Dead Code가 슬라이스에 포함됨

다음과 같이 상수 또는 사실상 상수인 조건이 포함된 테스트에서 실행되지 않는 분기의 대입이 슬라이스에 반복적으로 포함됨
```
if (privateTrue)
{
    data = 2;
}
else
{
    data = 0;  // Dead Code
}
```
실제 실행 경로에서는 data = 0이 수행되지 않지만, 결과에는 해당 노드가 포함되어 있었음

이는 Joern이 privateTrue, privateFalse, STATIC_FINAL_FIVE 등의 실제 값을 평가하여 불가능한 CFG 분기를 제거하지 않기 때문에, 
실행되지 않는 else의 대입도 reaching definition으로 포함되는 문제로 보임. 

Sink에서 전체 DDG를 다시 역추적하지 않는 방법으로 스크립트의 추적 방식을 고도화할 필요가 있음. 
이와 관련되서 else, case, 배열 선언 등 구문 문맥의 누락이 발생하는 문제가 존재함. 

예를 들어서 배열 인덱스 취약점에서 `if (data >= 0 && data < array.length)` 이런 조건은 추출 되지만, 실제 배열 선언은 포함되지 않은 경우가 있었음
이러한 경우 출력 결과가 취약점 설명에 필요한 구문적 문맥을 충분히 복원하지 못하는 문제가 발생할 수 있지 않을까 하는 우려가 생김
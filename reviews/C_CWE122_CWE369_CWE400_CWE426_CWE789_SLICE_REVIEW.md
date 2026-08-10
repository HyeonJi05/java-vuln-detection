# 슬라이싱 결과 수동 검토 메모

## 검토 정보

- 검토자: 최주언
- 검토일: 2026/08/07
- 담당 CWE: CWE-122, CWE-369, CWE-400, CWE-426, CWE-789

## 검토 대상 요약

CWE 5개(랜덤 선정)에서 testcase 3개씩 선택 (seed=20260807)

| 번호 | CWE | Testcase index | 대표 C/C++ 파일명 | Flow 유형 |
|---:|---:|---:|---|---|
| 1 | 122 | 472 | CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c / 67b.c | b2b, b2g, g2b |
| 2 | 122 | 2566 | CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c | b2b, g2b |
| 3 | 122 | 3575 | CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62a.cpp / 62b.cpp | b2b, g2b |
| 4 | 369 | 297 | CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | b2b, b2g1, b2g2, g2b1, g2b2 |
| 5 | 369 | 488 | CWE369_Divide_by_Zero__int_fscanf_divide_08.c | b2b, b2g1, b2g2, g2b1, g2b2 |
| 6 | 369 | 846 | CWE369_Divide_by_Zero__int_zero_modulo_51a.c / 51b.c | b2b, b2g, g2b |
| 7 | 400 | 106 | CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | b2b, b2g1, b2g2, g2b1, g2b2 |
| 8 | 400 | 505 | CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | b2b, b2g, g2b |
| 9 | 400 | 651 | CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | b2b, b2g, g2b |
| 10 | 426 | 15 | CWE426_Untrusted_Search_Path__char_popen_15.c | b2b, g2b1, g2b2 |
| 11 | 426 | 22 | CWE426_Untrusted_Search_Path__char_popen_32.c | b2b, g2b |
| 12 | 426 | 156 | CWE426_Untrusted_Search_Path__wchar_t_system_12.c | b2b, g2b |
| 13 | 789 | 236 | CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74a.cpp / 74b.cpp | b2b, b2g, g2b |
| 14 | 789 | 551 | CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp | b2b, b2g, g2b |
| 15 | 789 | 701 | CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp | b2b, b2g, g2b |

## Testcase별 검토

### [1] CWE-122 / Testcase 472

- C/C++ 파일명:
    - CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c
    - CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe122.txt


#### (1) Flow1 b2b

- Source: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c:37
- Sink: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c:41

**슬라이싱 결과**
```
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=37, col=5 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=37, col=12 | RAND32()
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=38, col=5 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=38, col=28 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=39, col=66 | myStruct

s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=27, col=67 | CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67_structType myStruct
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=29, col=9 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=29, col=16 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=41, col=9 | if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=41, col=13 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=41, col=13 | data >= 0
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=41, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- `CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=41` 에서 여러 라인(41~53)에 걸친 if문 전체에 대한 노드를 출력
- 하지만 LLM 프롬프트의 입력이 되는 트레이스(train, test)는 joern slicing 결과에 포함된 라인을 파싱한 후, 원본 소스코드에서 해당 라인을 그대로 가져오기 때문에 41 라인의 if 조건만 가져옴. 이 부분은 LLM 입력으로 전달할때 문제되는 부분은 아님.

    - 실제로 LLM에게 전달되는 트레이스

        ```txt
            data = RAND32();
            myStruct.structFirst = data;
            CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b_badSink(myStruct);

        void CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b_badSink(CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67_structType myStruct)
            int data = myStruct.structFirst;
                if (data >= 0)
        ```
- sink 부분에서, if 조건 위에 주석이 있어서 실제 sink 라인(`buffer[data] = 1;`)은 트레이스에 포함되지 않음.

#### (2) Flow2 b2g

- Source: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c:72
- Sink: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c:108

**슬라이싱 결과**
```
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=72, col=5 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=72, col=12 | RAND32()
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=73, col=5 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=73, col=28 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=74, col=70 | myStruct

s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=95, col=71 | CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67_structType myStruct
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=97, col=9 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=97, col=16 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=9 | if (data >= 0 && data < (10))
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is out-of-bounds");
        }
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=13 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=13 | data >= 0
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=13 | data >= 0 && data < (10)
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=21 | 0
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=26 | data < (10)
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=26 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=108, col=34 | 10
```

**검토 결과**
- 분류 : 부족
- Flow1 b2b와 같은 케이스.

#### (3) Flow3 g2b

- Source: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c:57
- Sink: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c:77

**슬라이싱 결과**
```
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=57, col=5 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=57, col=12 | 7
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=58, col=5 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=58, col=28 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67a.c | line=59, col=70 | myStruct

s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=63, col=71 | CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67_structType myStruct
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=65, col=9 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=65, col=16 | myStruct.structFirst
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=77, col=9 | if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=77, col=13 | data
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=77, col=13 | data >= 0
s06/CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_67b.c | line=77, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- Flow1 b2b, Flow2 b2g와 같은 케이스.



### [2] CWE-122 / Testcase 2566

- C/C++ 파일명: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe122.txt

#### (1) Flow1 b2b

- Source: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c:32
- Sink: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c:44

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- dataPtr1, dataPtr2가 동일한 변수(&data)를 가리키는 이중 포인터인데, joern C가 이 둘이 같은 메모리를 가리킨다는 걸 판단하는 분석을 지원하지 않음
- 그래서 "malloc 결과를 *dataPtr1에 씀(`*dataPtr1 = data;`)"과 "*dataPtr2에서 읽음(`char * data = *dataPtr2;`)"이 CPG 상에서 서로 다른 대상으로 취급되어 DDG 엣지가 끊김

    ```
    char * data;
    char * *dataPtr1 = &data;
    char * *dataPtr2 = &data;
    data = NULL;
    {
        char * data = *dataPtr1;
        /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
        data = (char *)malloc(50*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0'; /* null terminate */
        *dataPtr1 = data;
    }
    {
        char * data = *dataPtr2;
        {
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
            strcat(data, source);
            printLine(data);
            free(data);
        }
    }
    ```

#### (2) Flow2 g2b

- Source: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c:65
- Sink: CWE122_Heap_Based_Buffer_Overflow__c_dest_char_cat_32.c:77

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스.



### [3] CWE-122 / Testcase 3575

- C/C++ 파일명:
    - CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62a.cpp
    - CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62b.cpp
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe122.txt

#### (1) Flow1 b2b

- Source: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62b.cpp:34
- Sink: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62a.cpp:45

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- source, sink가 반대로 지정되어 DDG 추출 실패함.
    - CWE122_..._62a.cpp:34~52 (source가 지정되길 예상했지만 sink로 지정됨)
        ```
        void bad()
        {
            wchar_t * data;
            data = NULL;
            badSource(data);
            {
                wchar_t source[10+1] = SRC_STRING;
                size_t i, sourceLen;
                sourceLen = wcslen(source);
                /* Copy length + 1 to include NUL terminator from source */
                /* POTENTIAL FLAW: data may not have enough space to hold source */
                for (i = 0; i < sourceLen + 1; i++)
                {
                    data[i] = source[i];
                }
                printWLine(data);
                delete [] data;
            }
        }
        ```
    - CWE122_..._62b.cpp:31~35 (sink가 지정되길 예상했지만 source로 지정됨)
        ```
        void badSource(wchar_t * &data)
        {
            /* FLAW: Did not leave space for a null terminator */
            data = new wchar_t[10];
        }
        ```

#### (2) Flow2 g2b

- Source: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62b.cpp:45
- Sink: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_loop_62a.cpp:72

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스.



### [4] CWE-369 / Testcase 297

- C/C++ 파일명: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe369.txt

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:70
- Sink: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:111

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=48, col=5 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=48, col=12 | -1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=48, col=13 | 1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=49, col=5 | if(GLOBAL_CONST_TRUE)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read data using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                ...

...

s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=108, col=5 | if(GLOBAL_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=108, col=8 | GLOBAL_CONST_TRUE != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=108, col=8 | <global> GLOBAL_CONST_TRUE
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=108, col=8 | 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=111, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=111, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=111, col=22 | 100
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=111, col=28 | data
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.

#### (2) Flow2 b2g1

- Source: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:146
- Sink: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:192

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=124, col=5 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=124, col=12 | -1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=124, col=13 | 1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=125, col=5 | if(GLOBAL_CONST_TRUE)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read data using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                ...

...

s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=192, col=9 | if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=192, col=13 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=192, col=13 | data != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=192, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- Flow1 b2b와 같이 여러 줄인 노드가 출력되며,
- if의 조건 위에 sink에 대한 주석이 있어 실제 sink(`printIntLine(100 / data);`)가 트레이스에 포함되지 않음.

#### (3) Flow3 b2g2

- Source: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:230
- Sink: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:271

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=208, col=5 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=208, col=12 | -1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=208, col=13 | 1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=209, col=5 | if(GLOBAL_CONST_TRUE)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read data using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                ...

...

s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=271, col=9 | if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=271, col=13 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=271, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- Flow2 b2g1와 같은 케이스. sink 라인(`printIntLine(100 / data);`)이 포함되지 않음.

#### (4) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:296
- Sink: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:301

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=287, col=5 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=287, col=12 | -1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=287, col=13 | 1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=288, col=5 | if(GLOBAL_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=288, col=8 | GLOBAL_CONST_FALSE != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=288, col=8 | <global> GLOBAL_CONST_FALSE
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=288, col=8 | 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=296, col=9 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=296, col=16 | 7
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=298, col=5 | if(GLOBAL_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=298, col=8 | GLOBAL_CONST_TRUE != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=298, col=8 | <global> GLOBAL_CONST_TRUE
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=298, col=8 | 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=301, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=301, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=301, col=22 | 100
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=301, col=28 | data
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.


#### (5) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:314
- Sink: CWE369_Divide_by_Zero__int_connect_socket_divide_09.c:319

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=310, col=5 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=310, col=12 | -1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=310, col=13 | 1
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=311, col=5 | if(GLOBAL_CONST_TRUE)
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=311, col=8 | GLOBAL_CONST_TRUE != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=311, col=8 | <global> GLOBAL_CONST_TRUE
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=311, col=8 | 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=314, col=9 | data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=314, col=16 | 7
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=316, col=5 | if(GLOBAL_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=316, col=8 | GLOBAL_CONST_TRUE != 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=316, col=8 | <global> GLOBAL_CONST_TRUE
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=316, col=8 | 0
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=319, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=319, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=319, col=22 | 100
s01/CWE369_Divide_by_Zero__int_connect_socket_divide_09.c | line=319, col=28 | data
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.


### [5] CWE-369 / Testcase 488

- C/C++ 파일명: CWE369_Divide_by_Zero__int_fscanf_divide_08.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe369.txt

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:43
- Sink: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:48

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=39, col=5 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=39, col=12 | -1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=39, col=13 | 1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=40, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Read data from the console using fscanf() */
        fscanf(stdin, "%d", &data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=40, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=43, col=16 | <unknown> stdin
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=43, col=23 | "%d"
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=43, col=29 | &data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=45, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=45, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=48, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=48, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=48, col=22 | 100
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=48, col=28 | data
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.

#### (2) Flow2 b2g1

- Source: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:65
- Sink: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:75

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=61, col=5 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=61, col=12 | -1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=61, col=13 | 1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=62, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Read data from the console using fscanf() */
        fscanf(stdin, "%d", &data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=62, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=65, col=16 | <unknown> stdin
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=65, col=23 | "%d"
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=65, col=29 | &data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=67, col=5 | if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: test for a zero denominator */
        if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=67, col=8 | staticReturnsFalse()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=75, col=9 | if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=75, col=13 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=75, col=13 | data != 0
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=75, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- Flow1 b2b와 같이 여러 줄인 노드가 출력되며,
- if의 조건 위에 sink에 대한 주석이 있어 실제 sink(`printIntLine(100 / data);`)가 트레이스에 포함되지 않음.

#### (3) Flow3 b2g2

- Source: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:95
- Sink: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:100

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=91, col=5 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=91, col=12 | -1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=91, col=13 | 1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=92, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Read data from the console using fscanf() */
        fscanf(stdin, "%d", &data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=92, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=95, col=16 | <unknown> stdin
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=95, col=23 | "%d"
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=95, col=29 | &data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=95, col=30 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=97, col=5 | if(staticReturnsTrue())
    {
        /* FIX: test for a zero denominator */
        if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=97, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=100, col=9 | if( data != 0 )
        {
            printIntLine(100 / data);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=100, col=13 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=100, col=21 | 0
```

**검토 결과**
- 분류 : 부족
- Flow2 b2g1와 같은 케이스. sink 라인(`printIntLine(100 / data);`)이 포함되지 않음.

#### (4) Flow4 g2b1

- Source: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:125
- Sink: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:130

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=116, col=5 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=116, col=12 | -1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=116, col=13 | 1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=117, col=5 | if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=117, col=8 | staticReturnsFalse()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=125, col=9 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=125, col=16 | 7
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=127, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=127, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=130, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=130, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=130, col=22 | 100
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=130, col=28 | data
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.

#### (5) Flow5 g2b2

- Source: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:143
- Sink: CWE369_Divide_by_Zero__int_fscanf_divide_08.c:148

**슬라이싱 결과**
```
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=139, col=5 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=139, col=12 | -1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=139, col=13 | 1
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=140, col=5 | if(staticReturnsTrue())
    {
        /* FIX: Use a value not equal to zero */
        data = 7;
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=140, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=143, col=9 | data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=143, col=16 | 7
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=145, col=5 | if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Possibly divide by zero */
        printIntLine(100 / data);
    }
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=145, col=8 | staticReturnsTrue()
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=148, col=9 | printIntLine(100 / data)
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=148, col=22 | 100 / data
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=148, col=22 | 100
s01/CWE369_Divide_by_Zero__int_fscanf_divide_08.c | line=148, col=28 | data
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.



### [6] CWE-369 / Testcase 846

- C/C++ 파일명:
    - CWE369_Divide_by_Zero__int_zero_modulo_51a.c
    - CWE369_Divide_by_Zero__int_zero_modulo_51b.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe369.txt

#### (1) Flow1 b2b

- Source: CWE369_Divide_by_Zero__int_zero_modulo_51a.c:31
- Sink: CWE369_Divide_by_Zero__int_zero_modulo_51b.c:25

**슬라이싱 결과**
```
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=31, col=5 | data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=31, col=12 | 0
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=32, col=56 | data

s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=22, col=57 | int data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=25, col=5 | printIntLine(100 % data)
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=25, col=18 | 100 % data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=25, col=18 | 100
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=25, col=24 | data
```

**검토 결과**
- 분류 : 정상

#### (2) Flow2 b2g

- Source: CWE369_Divide_by_Zero__int_zero_modulo_51a.c:61
- Sink: CWE369_Divide_by_Zero__int_zero_modulo_51b.c:43

**슬라이싱 결과**
```
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=61, col=5 | data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=61, col=12 | 0
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=62, col=60 | data

s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=40, col=61 | int data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=43, col=5 | if( data != 0 )
    {
        printIntLine(100 % data);
    }
    else
    {
        printLine("This would result in a divide by zero");
    }
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=43, col=9 | data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=43, col=9 | data != 0
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=43, col=17 | 0
```

**검토 결과**
- 분류 : 부족
- [4] CWE-369 / Testcase 297 - Flow3 b2g2와 같은 케이스. sink 라인(`printIntLine(100 % data);`)이 포함되지 않음.

#### (3) Flow3 g2b

- Source: CWE369_Divide_by_Zero__int_zero_modulo_51a.c:48
- Sink: CWE369_Divide_by_Zero__int_zero_modulo_51b.c:36

**슬라이싱 결과**
```
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=48, col=5 | data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=48, col=12 | 7
s02/CWE369_Divide_by_Zero__int_zero_modulo_51a.c | line=49, col=60 | data

s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=33, col=61 | int data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=36, col=5 | printIntLine(100 % data)
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=36, col=18 | 100 % data
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=36, col=18 | 100
s02/CWE369_Divide_by_Zero__int_zero_modulo_51b.c | line=36, col=24 | data
```

**검토 결과**
- 분류 : 정상


### [7] CWE-400 / Testcase 106

- C/C++ 파일명: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe400.txt

#### (1) Flow1 b2b

- Source: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:76
- Sink: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:117

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=54, col=5 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=54, col=13 | -1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=54, col=14 | 1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=55, col=5 | if(globalTrue)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read count using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                if (co...

...

s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=114, col=5 | if(globalTrue)
    {
        /* POTENTIAL FLAW: Sleep function using count as the parameter with no validation */
        SLEEP(count);
        printLine("Sleep time possibly too long");
    }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=114, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=114, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=114, col=8 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=117, col=9 | usleep(count)
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=117, col=9 | SLEEP(count)
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=117, col=15 | count
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.

#### (2) Flow2 b2g1

- Source: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:153
- Sink: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:199

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=131, col=5 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=131, col=13 | -1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=131, col=14 | 1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=132, col=5 | if(globalTrue)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read count using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                if (co...
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=132, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=132, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=132, col=8 | 0

...

s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=9 | if (count > 0 && count <= 2000)
        {
            SLEEP(count);
            printLine("Sleep time OK");
        }
        else
        {
            printLine("Sleep time too long");
        }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=13 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=13 | count > 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=13 | count > 0 && count <= 2000
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=21 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=26 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=26 | count <= 2000
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=199, col=35 | 2000
```

**검토 결과**
- 분류 : 부족
- Flow1 b2b와 같이 여러 줄인 노드가 출력되며,
- if의 조건 위에 sink에 대한 주석이 있어 실제 sink(`SLEEP(count);`)가 트레이스에 포함되지 않음.

#### (3) Flow3 b2g2

- Source: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:238
- Sink: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:279

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=216, col=5 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=216, col=13 | -1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=216, col=14 | 1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=217, col=5 | if(globalTrue)
    {
        {
#ifdef _WIN32
            WSADATA wsaData;
            int wsaDataInit = 0;
#endif
            int recvResult;
            struct sockaddr_in service;
            SOCKET connectSocket = INVALID_SOCKET;
            char inputBuffer[CHAR_ARRAY_SIZE];
            do
            {
#ifdef _WIN32
                if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
                {
                    break;
                }
                wsaDataInit = 1;
#endif
                /* POTENTIAL FLAW: Read count using a connect socket */
                connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (connectSocket == INVALID_SOCKET)
                {
                    break;
                }
                memset(&service, 0, sizeof(service));
                service.sin_family = AF_INET;
                service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
                service.sin_port = htons(TCP_PORT);
                if (co...
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=217, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=217, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=217, col=8 | 0

...

s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=9 | if (count > 0 && count <= 2000)
        {
            SLEEP(count);
            printLine("Sleep time OK");
        }
        else
        {
            printLine("Sleep time too long");
        }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=13 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=13 | count > 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=13 | count > 0 && count <= 2000
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=21 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=26 | count <= 2000
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=26 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=279, col=35 | 2000
```

**검토 결과**
- 분류 : 부족
- Flow3 b2g1와 같은 케이스. sink 라인(`SLEEP(count);`)이 포함되지 않음.

#### (4) Flow4 g2b1

- Source: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:305
- Sink: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:310

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=296, col=5 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=296, col=13 | -1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=296, col=14 | 1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=297, col=5 | if(globalFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Use a relatively small number */
        count = 20;
    }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=297, col=8 | globalFalse != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=297, col=8 | <global> globalFalse
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=297, col=8 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=305, col=9 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=305, col=17 | 20
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=307, col=5 | if(globalTrue)
    {
        /* POTENTIAL FLAW: Sleep function using count as the parameter with no validation */
        SLEEP(count);
        printLine("Sleep time possibly too long");
    }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=307, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=307, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=307, col=8 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=310, col=9 | usleep(count)
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=310, col=9 | SLEEP(count)
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=310, col=15 | count
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.

#### (5) Flow5 g2b2

- Source: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:324
- Sink: CWE400_Resource_Exhaustion__connect_socket_sleep_10.c:329

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=320, col=5 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=320, col=13 | -1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=320, col=14 | 1
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=321, col=5 | if(globalTrue)
    {
        /* FIX: Use a relatively small number */
        count = 20;
    }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=321, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=321, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=321, col=8 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=324, col=9 | count
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=324, col=17 | 20
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=326, col=5 | if(globalTrue)
    {
        /* POTENTIAL FLAW: Sleep function using count as the parameter with no validation */
        SLEEP(count);
        printLine("Sleep time possibly too long");
    }
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=326, col=8 | globalTrue != 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=326, col=8 | <global> globalTrue
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=326, col=8 | 0
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=329, col=9 | SLEEP(count)
s01/CWE400_Resource_Exhaustion__connect_socket_sleep_10.c | line=329, col=15 | count
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스.


### [8] CWE-400 / Testcase 505

- C/C++ 파일명: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe400.txt

#### (1) Flow1 b2b

- Source: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:98
- Sink: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:59

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=46, col=21 | int count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=9 | for (i = 0;i < (size_t)count;i++)
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=14 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=18 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=21 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=21 | i < (size_t)count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=25 | (size_t)count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=33 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=40 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=59, col=40 | i++
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=77, col=5 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=77, col=13 | -1
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=77, col=14 | 1

...

s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=13 | if (recvResult == SOCKET_ERROR || recvResult == 0)
            {
                break;
            }
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=17 | recvResult == SOCKET_ERROR || recvResult == 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=17 | recvResult == SOCKET_ERROR
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=17 | recvResult
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=31 | SOCKET_ERROR
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=47 | recvResult == 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=47 | recvResult
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=122, col=61 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=127, col=13 | inputBuffer[recvResult]
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=127, col=39 | '\0'
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=129, col=13 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=129, col=21 | atoi(inputBuffer)
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=129, col=26 | inputBuffer
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=131, col=16 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=147, col=13 | count
```

**검토 결과**
- 분류 : 부족
- sink가 `for (i<count)` 반복문 조건이라, 실제 자원 소비 동작인 `fwrite`(반복문 내부, line=61)가 트레이스에 포함되지 않아 취약 판단 근거가 불완전함.

#### (2) Flow2 b2g

- Source: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:244
- Sink: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:200

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=193, col=25 | int count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=9 | if (count > 0 && count <= 20)
        {
            pFile = fopen(filename, "w+");
            if (pFile == NULL)
            {
                exit(1);
            }
            for (i = 0; i < (size_t)count; i++)
            {
                if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile)) exit(1);
            }
            if (pFile)
            {
                fclose(pFile);
            }
        }
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=13 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=13 | count > 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=13 | count > 0 && count <= 20
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=21 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=26 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=26 | count <= 20
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=200, col=35 | 20

...

s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=273, col=13 | inputBuffer[recvResult]
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=273, col=39 | '\0'
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=275, col=13 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=275, col=21 | atoi(inputBuffer)
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=275, col=26 | inputBuffer
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=277, col=16 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=293, col=17 | count
```

**검토 결과**
- 분류 : 부족
- sink가 `if (count>0 && count<=20)` 검증 조건이라, 그 검증이 보호하는 `fwrite`(if문 내부, line=209)가 트레이스에 포함되지 않아 정상 판단 근거가 불완전함.

#### (3) Flow3 g2b

- Source: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:188
- Sink: CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c:168

**슬라이싱 결과**
```
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=155, col=25 | int count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=9 | for (i = 0;i < (size_t)count;i++)
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=14 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=18 | 0
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=21 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=21 | i < (size_t)count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=25 | (size_t)count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=33 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=40 | i
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=168, col=40 | i++
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=188, col=5 | count
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=188, col=13 | 20
s01/CWE400_Resource_Exhaustion__listen_socket_fwrite_41.c | line=189, col=17 | count
```

**검토 결과**
- 분류 : 부족
- sink가 `for (i<count)` 반복문 조건이라, 실제 자원 소비 동작인 `fwrite`(반복문 내부, line=170)가 트레이스에 포함되지 않아 취약 판단 근거가 불완전함.



### [9] CWE-400 / Testcase 651

- C/C++ 파일명: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe400.txt

#### (1) Flow1 b2b

- Source: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:30
- Sink: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:50

**슬라이싱 결과**
```
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=27, col=23 | int &count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=30, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=30, col=13 | RAND32()
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=37, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=37, col=13 | -1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=37, col=14 | 1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=38, col=15 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=9 | for (i = 0;i < (size_t)count;i++)
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=14 | i
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=18 | 0
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=21 | i
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=21 | i < (size_t)count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=25 | (size_t)count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=33 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=40 | i
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=50, col=40 | i++
```

**검토 결과**
- 분류 : 부족
- [8] CWE-400 / Testcase 505 - Flow1 b2b와 같은 케이스. sink가 `for` 반복문 조건이라 실제 자원 소비 동작인 `fwrite`(line=52)가 트레이스에 포함되지 않음.

#### (2) Flow2 b2g

- Source: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:110
- Sink: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:124

**슬라이싱 결과**
```
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=107, col=27 | int &count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=110, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=110, col=13 | RAND32()
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=117, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=117, col=13 | -1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=117, col=14 | 1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=118, col=19 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=9 | if (count > 0 && count <= 20)
        {
            pFile = fopen(filename, "w+");
            if (pFile == NULL)
            {
                exit(1);
            }
            for (i = 0; i < (size_t)count; i++)
            {
                if (strlen(SENTENCE) != fwrite(SENTENCE, sizeof(char), strlen(SENTENCE), pFile)) exit(1);
            }
            if (pFile)
            {
                fclose(pFile);
            }
        }
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=13 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=13 | count > 0
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=13 | count > 0 && count <= 20
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=21 | 0
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=26 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=26 | count <= 20
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=124, col=35 | 20
```

**검토 결과**
- 분류 : 부족
- [8] CWE-400 / Testcase 505 - Flow2 b2g와 같은 케이스. sink가 검증 조건이라 그 검증이 보호하는 `fwrite`(line=133)가 트레이스에 포함되지 않음.

#### (3) Flow3 g2b

- Source: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:72
- Sink: CWE400_Resource_Exhaustion__rand_fwrite_43.cpp:92

**슬라이싱 결과**
```
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=69, col=27 | int &count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=72, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=72, col=13 | 20
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=79, col=5 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=79, col=13 | -1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=79, col=14 | 1
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=80, col=19 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=9 | for (i = 0;i < (size_t)count;i++)
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=14 | i
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=18 | 0
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=21 | i
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=21 | i < (size_t)count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=25 | (size_t)count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=33 | count
s02/CWE400_Resource_Exhaustion__rand_fwrite_43.cpp | line=92, col=40 | i
```

**검토 결과**
- 분류 : 부족
- [8] CWE-400 / Testcase 505 - Flow1 b2b와 같은 케이스. sink가 `for` 반복문 조건이라 실제 자원 소비 동작인 `fwrite`(line=94)가 트레이스에 포함되지 않음.

### [10] CWE-426 / Testcase 15

- C/C++ 파일명: CWE426_Untrusted_Search_Path__char_popen_15.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe426.txt

#### (1) Flow1 b2b

- Source: CWE426_Untrusted_Search_Path__char_popen_15.c:54
- Sink: CWE426_Untrusted_Search_Path__char_popen_15.c:65

**슬라이싱 결과**
```
CWE426_Untrusted_Search_Path__char_popen_15.c | line=48, col=10 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=48, col=28 | ""
CWE426_Untrusted_Search_Path__char_popen_15.c | line=49, col=5 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=49, col=12 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=50, col=5 | switch(6)
    {
    case 6:
        /* FLAW: the full path is not specified */
        strcpy(data, BAD_OS_COMMAND);
        break;
    default:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    }
CWE426_Untrusted_Search_Path__char_popen_15.c | line=50, col=12 | 6
CWE426_Untrusted_Search_Path__char_popen_15.c | line=54, col=16 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=54, col=22 | BAD_OS_COMMAND
CWE426_Untrusted_Search_Path__char_popen_15.c | line=65, col=16 | popen(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=65, col=16 | POPEN(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=65, col=22 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=65, col=28 | "wb"
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.

#### (2) Flow2 g2b1

- Source: CWE426_Untrusted_Search_Path__char_popen_15.c:91
- Sink: CWE426_Untrusted_Search_Path__char_popen_15.c:98

**슬라이싱 결과**
```
CWE426_Untrusted_Search_Path__char_popen_15.c | line=81, col=10 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=81, col=28 | ""
CWE426_Untrusted_Search_Path__char_popen_15.c | line=82, col=5 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=82, col=12 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=83, col=5 | switch(5)
    {
    case 6:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    default:
        /* FIX: full path is specified */
        strcpy(data, GOOD_OS_COMMAND);
        break;
    }
CWE426_Untrusted_Search_Path__char_popen_15.c | line=83, col=12 | 5
CWE426_Untrusted_Search_Path__char_popen_15.c | line=91, col=16 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=91, col=22 | GOOD_OS_COMMAND
CWE426_Untrusted_Search_Path__char_popen_15.c | line=98, col=16 | popen(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=98, col=16 | POPEN(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=98, col=22 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=98, col=28 | "wb"
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.


#### (3) Flow3 g2b2

- Source: CWE426_Untrusted_Search_Path__char_popen_15.c:116
- Sink: CWE426_Untrusted_Search_Path__char_popen_15.c:127

**슬라이싱 결과**
```
CWE426_Untrusted_Search_Path__char_popen_15.c | line=110, col=10 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=110, col=28 | ""
CWE426_Untrusted_Search_Path__char_popen_15.c | line=111, col=5 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=111, col=12 | dataBuffer
CWE426_Untrusted_Search_Path__char_popen_15.c | line=112, col=5 | switch(6)
    {
    case 6:
        /* FIX: full path is specified */
        strcpy(data, GOOD_OS_COMMAND);
        break;
    default:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    }
CWE426_Untrusted_Search_Path__char_popen_15.c | line=112, col=12 | 6
CWE426_Untrusted_Search_Path__char_popen_15.c | line=116, col=16 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=116, col=22 | GOOD_OS_COMMAND
CWE426_Untrusted_Search_Path__char_popen_15.c | line=127, col=16 | popen(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=127, col=16 | POPEN(data, "wb")
CWE426_Untrusted_Search_Path__char_popen_15.c | line=127, col=22 | data
CWE426_Untrusted_Search_Path__char_popen_15.c | line=127, col=28 | "wb"
```

**검토 결과**
- 분류 : 정상
- [1] CWE-122 / Testcase 472 의 경우처럼 여러 라인에 걸친 하나의 노드가 전부 출력되지만, 라인넘버만 봤을 때 결과는 정상.

### [11] CWE-426 / Testcase 22

- C/C++ 파일명: CWE426_Untrusted_Search_Path__char_popen_32.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe426.txt

#### (1) Flow1 b2b

- Source: CWE426_Untrusted_Search_Path__char_popen_32.c:55
- Sink: CWE426_Untrusted_Search_Path__char_popen_32.c:64

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- [2] CWE-122 / Testcase 2566와 같은 케이스. 이중 포인터 분석 실패 문제


#### (2) Flow2 g2b

- Source: CWE426_Untrusted_Search_Path__char_popen_32.c:88
- Sink: CWE426_Untrusted_Search_Path__char_popen_32.c:97

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스.

### [12] CWE-426 / Testcase 156

- C/C++ 파일명: CWE426_Untrusted_Search_Path__wchar_t_system_12.c
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe426.txt

#### (1) Flow1 b2b

- Source: CWE426_Untrusted_Search_Path__wchar_t_system_12.c:51
- Sink: CWE426_Untrusted_Search_Path__wchar_t_system_12.c:60

**슬라이싱 결과**
```
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=46, col=13 | dataBuffer
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=46, col=31 | L""
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=47, col=5 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=47, col=12 | dataBuffer
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=48, col=5 | if(globalReturnsTrueOrFalse())
    {
        /* FLAW: the full path is not specified */
        wcscpy(data, BAD_OS_COMMAND);
    }
    else
    {
        /* FIX: full path is specified */
        wcscpy(data, GOOD_OS_COMMAND);
    }
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=48, col=8 | globalReturnsTrueOrFalse()
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=51, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=51, col=22 | BAD_OS_COMMAND
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=56, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=56, col=22 | GOOD_OS_COMMAND
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=60, col=5 | if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=60, col=9 | SYSTEM(data)
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=60, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=60, col=25 | 0
```

**검토 결과**
- 분류 : 부족
- `wcscpy(data, BAD_OS_COMMAND);`(line=51)과 `wcscpy(data, GOOD_OS_COMMAND);`(line=56)은 if/else라서 둘 중 하나만 실행되는데, 트레이스는 else 라인이 없어 둘 다 실행되는 것처럼 보임.

#### (2) Flow2 g2b

- Source: CWE426_Untrusted_Search_Path__wchar_t_system_12.c:81
- Sink: CWE426_Untrusted_Search_Path__wchar_t_system_12.c:90

**슬라이싱 결과**
```
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=76, col=13 | dataBuffer
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=76, col=31 | L""
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=77, col=5 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=77, col=12 | dataBuffer
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=78, col=5 | if(globalReturnsTrueOrFalse())
    {
        /* FIX: full path is specified */
        wcscpy(data, GOOD_OS_COMMAND);
    }
    else
    {
        /* FIX: full path is specified */
        wcscpy(data, GOOD_OS_COMMAND);
    }
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=78, col=8 | globalReturnsTrueOrFalse()
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=81, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=81, col=22 | GOOD_OS_COMMAND
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=86, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=86, col=22 | GOOD_OS_COMMAND
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=90, col=5 | if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=90, col=9 | system(data)
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=90, col=9 | SYSTEM(data)
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=90, col=16 | data
CWE426_Untrusted_Search_Path__wchar_t_system_12.c | line=90, col=25 | 0
```

**검토 결과**
- 분류 : 정상
- Flow1 b2b와 같은 케이스이지만, if/else 둘다 실행하는 작업(`wcscpy(data, GOOD_OS_COMMAND);`)이 같아서 else가 포함되지 않은게 영향을 미치지 않음.

### [13] CWE-789 / Testcase 236

- C/C++ 파일명:
    - CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74a.cpp
    - CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74b.cpp
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe789.txt

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74a.cpp:42
- Sink: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74b.cpp:43

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- `bad()`에서 `dataMap[2] = data;`로 저장한 값을 `badSink()`에서 `size_t data = dataMap[2];`로 다시 꺼내 쓰는데, Joern이 `map<int,size_t>`의 [] 연산을 해석하지 못하고 이름 모를 함수 호출로만 취급함. 그래서 저장한 값과 조회한 값이 같다는 걸 못 알아채고 DDG가 끊김. [1] CWE-122 / Testcase 2566의 이중 포인터 문제와 유사한 유형.

#### (2) Flow2 b2g

- Source: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74a.cpp:82
- Sink: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74b.cpp:97

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodB2G()`의 `dataMap[2] = data;`를 `goodB2GSink()`의 `dataMap[2]`로 읽음.

#### (3) Flow3 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74a.cpp:64
- Sink: CWE789_Uncontrolled_Mem_Alloc__malloc_char_rand_74b.cpp:72

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodG2B()`의 `dataMap[2] = data;`를 `goodG2BSink()`의 `dataMap[2]`로 읽음.



### [14] CWE-789 / Testcase 551

- C/C++ 파일명: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe789.txt

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:42
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:59

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- `bad()`에서 `size_t &dataRef = data;`로 참조자를 선언하고 `data = strtoul(...)`로 값을 대입한 뒤, 안쪽 블록에서 `size_t data = dataRef;`로 다시 꺼내 쓰는데, Joern이 `dataRef`가 `data`와 같은 저장 공간을 가리킨다는 걸 추적하지 못해 DDG가 끊김. [1] CWE-122 / Testcase 2566의 이중 포인터 문제와 유사한 유형.

#### (2) Flow2 b2g

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:121
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:138

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodB2G()`도 동일하게 `size_t &dataRef = data;`를 통해 값을 전달함.

#### (3) Flow3 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:87
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_33.cpp:95

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodG2B()`도 동일하게 `size_t &dataRef = data;`를 통해 값을 전달함.



### [15] CWE-789 / Testcase 701

- C/C++ 파일명: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp
- 슬라이싱 결과 파일: slicing/output/slice_results/c/slice_results_260804_201010/cwe789.txt

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:64
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:43

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- `bad()`에서 `badData = data;`(65번)로 전역변수에 값을 쓰고, 인자 없이 `badSink()`를 호출하면 그 안에서 `size_t data = badData;`(37번)로 다시 읽는데, Joern이 전역/static 변수를 통한 함수 간 데이터 전달을 추적하지 못해 DDG가 끊김.

#### (2) Flow2 b2g

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:138
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:117

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodB2G()`도 동일하게 `goodB2GData` 전역변수를 통해 값을 전달함.

#### (3) Flow3 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:103
- Sink: CWE789_Uncontrolled_Mem_Alloc__new_char_rand_45.cpp:82

**슬라이싱 결과**
```
No data-flow path found.
```

**검토 결과**
- 분류 : 실패
- Flow1 b2b와 같은 케이스. `goodG2B()`도 동일하게 `goodG2BData` 전역변수를 통해 값을 전달함.

## 검토 결과 요약

- 총 15개 Testcase, 47개 Flow 검토

### CWE별 분류 현황

| CWE | Testcase 수 | Flow 수 | 정상 | 부족 | 실패 |
|---|---:|---:|---:|---:|---:|
| CWE-122 | 3 | 7 | 0 | 3 | 4 |
| CWE-369 | 3 | 13 | 8 | 5 | 0 |
| CWE-400 | 3 | 11 | 3 | 8 | 0 |
| CWE-426 | 3 | 7 | 4 | 1 | 2 |
| CWE-789 | 3 | 9 | 0 | 0 | 9 |
| **합계** | **15** | **47** | **15** | **17** | **15** |

### 부족(17건) 원인별 분류

| 원인 유형 | 건수 | 설명 |
|---|---:|---|
| sink가 조건/반복문이라 실제 sink 라인 누락 | 16 | sink가 `if`/`for` 조건으로 지정되어, 실제 sink가 되는 라인(`buffer[data]=1`, `SLEEP(count)`, `fwrite` 등)이 트레이스에 포함되지 않음 |
| else 라인이 없어 둘 다 실행되는 것처럼 보임 | 1 | if가 참이면 위험한 값을, else면 안전한 값을 쓰는 구조인데, 트레이스에는 else 표시 없이 두 값이 그냥 순서대로 나열되어 "위험한 값을 안전한 값으로 덮어쓴 것"처럼 보임. 그러면 실제로는 조건에 따라 위험한 값이 그대로 sink까지 전달될 수 있다는 사실을 놓치게 됨 |

### 실패(15건) 원인별 분류

| 원인 유형 | 건수 | 설명 |
|---|---:|---|
| 포인터·컨테이너·참조자 별칭을 못 쫓아감 | 10 | 이중 포인터(4건) - dataPtr1, dataPtr2가 동일한 변수(&data)를 가리키는데 joern C가 이 둘이 같은 메모리를 가리킨다는 걸 판단하는 분석을 지원하지 않음 / 컨테이너 key 조회 `map[]`(3건) - Joern이 `map<int,size_t>`의 `[]` 연산을 key 기반 조회로 해석하지 못해 저장한 값과 조회한 값이 같다는 걸 못 알아챔 / C++ 참조자 `&`(3건) - Joern이 `dataRef`가 `data`와 같은 저장 공간을 가리킨다는 걸 추적하지 못함 → 모두 DDG가 끊김 |
| source/sink 라인이 서로 바뀌어 지정됨 | 2 | source, sink가 반대로 지정되어 DDG 추출 실패함 |
| 전역변수로 전달되는 값을 못 쫓아감 | 3 | Joern이 전역/static 변수를 통한 함수 간 데이터 전달을 추적하지 못해 DDG가 끊김 |

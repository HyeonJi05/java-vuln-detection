# 슬라이싱 결과 수동 검토 메모

## 검토 정보

- 검토자: 
- 검토일: 
- 담당 CWE: CWE-113, CWE-789

## 검토 대상 요약

CWE 2개에서 testcase 5개씩 선택

| 번호 | CWE | Testcase index | 대표 Java 파일명 | Flow 유형 |
|---:|---:|---:|---|---|
| 1 | 113 | 1310 | CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 2 | 113 | 229 | CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 3 | 113 | 52 | CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 4 | 113 | 564 | CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | b2b, b2g1, b2g2, g2b1, g2b2 |
| 5 | 113 | 502 | CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | g2b (jobs에 flow3만 포함) |
| 6 | 789 | 1044 | CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | b2b, g2b1, g2b2 |
| 7 | 789 | 1011 | CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | b2b, g2b |
| 8 | 789 | 187 | CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | g2b1, g2b2 (jobs에 flow2·flow3만 포함) |
| 9 | 789 | 1565 | CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68*.java | b2b, g2b |
| 10 | 789 | 97 | CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | b2b, g2b |

## Testcase별 검토

### [1] CWE-113 / Testcase 1310

- Java 파일명: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java

#### (1) Flow1 b2b

- Source: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:58
- Sink: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:131

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=39 | switch (6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=50 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=52 | listener = new ServerSocket(39543);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=53 | socket = listener.accept();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=56 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=58 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=121 | data = null;
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=125 | switch (7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=128 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131 | response.setHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=35, col=49 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=39, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=39, col=17 | 6
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=50, col=17 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=52, col=21 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=52, col=32 | new ServerSocket(39543)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=52, col=49 | 39543
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=53, col=21 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=53, col=30 | listener.accept()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=53, col=30 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55, col=63 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=55, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=56, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=56, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=56, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=58, col=21 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=58, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=58, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=121, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=121, col=20 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=125, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=125, col=17 | 7
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=128, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=128, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=128, col=17 | data != null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=128, col=25 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131, col=17 | response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131, col=17 | response.setHeader("Location", "/author.jsp?lang=" + data)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131, col=36 | "Location"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131, col=48 | "/author.jsp?lang=" + data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=131, col=70 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (2) Flow2 b2g1

- Source: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:233
- Sink: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:310

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=214 | switch (6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=225 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=227 | listener = new ServerSocket(39543);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=228 | socket = listener.accept();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=231 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=233 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=296 | data = null;
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=300 | switch (8)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=307 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310 | data = URLEncoder.encode(data, "UTF-8");
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=214, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=214, col=17 | 6
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=225, col=17 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=227, col=21 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=227, col=32 | new ServerSocket(39543)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=227, col=49 | 39543
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=228, col=21 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=228, col=30 | listener.accept()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=228, col=30 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230, col=63 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=230, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=231, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=231, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=231, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=233, col=21 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=233, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=233, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=296, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=296, col=20 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=300, col=9 | switch(8)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=300, col=17 | 8
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=307, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=307, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=307, col=17 | data != null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=307, col=25 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=17 | data = URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=24 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=24 | URLEncoder
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=42 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=310, col=48 | "UTF-8"
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (3) Flow3 b2g2

- Source: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:341
- Sink: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:414

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=322 | switch (6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=333 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=335 | listener = new ServerSocket(39543);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=336 | socket = listener.accept();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=339 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=341 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=404 | data = null;
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=408 | switch (7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=411 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414 | data = URLEncoder.encode(data, "UTF-8");
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=322, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=322, col=17 | 6
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=333, col=17 | try
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=335, col=21 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=335, col=32 | new ServerSocket(39543)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=335, col=49 | 39543
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=336, col=21 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=336, col=30 | listener.accept()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=336, col=30 | listener
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338, col=63 | socket
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=338, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=339, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=339, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=339, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=341, col=21 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=341, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=341, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=404, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=404, col=20 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=408, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=408, col=17 | 7
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=411, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=411, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=411, col=17 | data != null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=411, col=25 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=17 | data = URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=24 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=24 | URLEncoder
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=42 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=414, col=48 | "UTF-8"
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (4) Flow4 g2b1

- Source: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:155
- Sink: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:165

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=146 | switch (5)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=151 | data = null;
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=155 | data = "foo";
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=159 | switch (7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=162 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=165 | response.setHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=142, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=146, col=9 | switch(5)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=146, col=17 | 5
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=151, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=151, col=20 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=155, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=155, col=20 | "foo"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=159, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=159, col=17 | 7
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=162, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=162, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=162, col=17 | data != null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=162, col=25 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=165, col=17 | response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=165, col=36 | "Location"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=165, col=48 | "/author.jsp?lang=" + data
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.setHeader(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


#### (5) Flow5 g2b2

- Source: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:184
- Sink: CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java:199

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=180 | switch (6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=184 | data = "foo";
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=189 | data = null;
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=193 | switch (7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=196 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199 | response.setHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=176, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=180, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=180, col=17 | 6
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=184, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=184, col=20 | "foo"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=189, col=13 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=189, col=20 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=193, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=193, col=17 | 7
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=196, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=196, col=17 | data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=196, col=17 | data != null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=196, col=25 | null
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199, col=17 | response
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199, col=17 | response.setHeader("Location", "/author.jsp?lang=" + data)
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199, col=36 | "Location"
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199, col=48 | "/author.jsp?lang=" + data
CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java | line=199, col=70 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


### [2] CWE-113 / Testcase 229

- Java 파일명: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java

#### (1) Flow1 b2b

- Source: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:54
- Sink: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:90

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=42 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=47 | Properties properties = new Properties();
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=49 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=51 | streamFileInput = new FileInputStream("../common/config.properties");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=52 | properties.load(streamFileInput);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=54 | data = properties.getProperty("data");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=81 | data = null;
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=84 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=86 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=88 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=90 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=39, col=5 | this
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=39, col=49 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=42, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=42, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=42, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=42, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=47, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=47, col=41 | new Properties()
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=49, col=17 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=51, col=21 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=51, col=39 | new FileInputStream("../common/config.properties")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=51, col=59 | "../common/config.properties"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=52, col=21 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=52, col=37 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=54, col=21 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=54, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=54, col=28 | properties.getProperty("data")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=54, col=51 | "data"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=81, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=81, col=20 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=84, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=84, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=84, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=84, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=86, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=86, col=17 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=86, col=17 | data != null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=86, col=25 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=88, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=88, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=88, col=48 | "lang"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=88, col=56 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=90, col=17 | response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=90, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


#### (2) Flow2 b2g1

- Source: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:167
- Sink: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:209

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=155 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=160 | Properties properties = new Properties();
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=162 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=164 | streamFileInput = new FileInputStream("../common/config.properties");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=165 | properties.load(streamFileInput);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=167 | data = properties.getProperty("data");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=194 | data = null;
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=197 | if (privateFive!=5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=205 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207 | Cookie cookieSink = new Cookie("lang", URLEncoder.encode(data, "UTF-8"));
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=209 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=152, col=5 | this
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=152, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=155, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=155, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=155, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=155, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=160, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=160, col=41 | new Properties()
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=162, col=17 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=164, col=21 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=164, col=39 | new FileInputStream("../common/config.properties")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=164, col=59 | "../common/config.properties"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=165, col=21 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=165, col=37 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=167, col=21 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=167, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=167, col=28 | properties.getProperty("data")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=167, col=51 | "data"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=194, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=194, col=20 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=197, col=9 | if (privateFive != 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=197, col=13 | privateFive != 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=197, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=197, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=205, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=205, col=17 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=205, col=17 | data != null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=205, col=25 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=37 | new Cookie("lang", URLEncoder.encode(data, "UTF-8"))
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=48 | "lang"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=56 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=56 | URLEncoder
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=74 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=207, col=80 | "UTF-8"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=209, col=17 | response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=209, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


#### (3) Flow3 b2g2

- Source: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:231
- Sink: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:267

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=219 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=224 | Properties properties = new Properties();
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=226 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=228 | streamFileInput = new FileInputStream("../common/config.properties");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=229 | properties.load(streamFileInput);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=231 | data = properties.getProperty("data");
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=258 | data = null;
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=261 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=263 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265 | Cookie cookieSink = new Cookie("lang", URLEncoder.encode(data, "UTF-8"));
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=267 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=216, col=5 | this
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=216, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=219, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=219, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=219, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=219, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=224, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=224, col=41 | new Properties()
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=226, col=17 | try
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=228, col=21 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=228, col=39 | new FileInputStream("../common/config.properties")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=228, col=59 | "../common/config.properties"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=229, col=21 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=229, col=37 | streamFileInput
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=231, col=21 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=231, col=28 | properties
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=231, col=28 | properties.getProperty("data")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=231, col=51 | "data"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=258, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=258, col=20 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=261, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=261, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=261, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=261, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=263, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=263, col=17 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=263, col=17 | data != null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=263, col=25 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=37 | new Cookie("lang", URLEncoder.encode(data, "UTF-8"))
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=48 | "lang"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=56 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=56 | URLEncoder
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=74 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=265, col=80 | "UTF-8"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=267, col=17 | response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=267, col=17 | response.addCookie(cookieSink)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=267, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (4) Flow4 g2b1

- Source: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:109
- Sink: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:119

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=99 | if (privateFive!=5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=103 | data = null;
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=109 | data = "foo";
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=113 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=115 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=117 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=119 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=96, col=5 | this
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=96, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=99, col=9 | if (privateFive != 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=99, col=13 | privateFive != 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=99, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=99, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=103, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=103, col=20 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=109, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=109, col=20 | "foo"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=113, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=113, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=113, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=113, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=115, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=115, col=17 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=115, col=17 | data != null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=115, col=25 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=117, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=117, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=117, col=48 | "lang"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=117, col=56 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=119, col=17 | response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=119, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


#### (5) Flow5 g2b2

- Source: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:131
- Sink: CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java:146

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=128 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=131 | data = "foo";
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=137 | data = null;
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=140 | if (privateFive==5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=142 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=144 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=146 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=125, col=5 | this
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=125, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=128, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=128, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=128, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=128, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=131, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=131, col=20 | "foo"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=137, col=13 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=137, col=20 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=140, col=9 | if (privateFive == 5)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=140, col=13 | privateFive == 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=140, col=13 | this.privateFive
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=140, col=26 | 5
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=142, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=142, col=17 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=142, col=17 | data != null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=142, col=25 | null
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=144, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=144, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=144, col=48 | "lang"
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=144, col=56 | data
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=146, col=17 | response
CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java | line=146, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


### [3] CWE-113 / Testcase 52

- Java 파일명: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java

#### (1) Flow1 b2b

- Source: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:36
- Sink: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:49

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=31 | switch (6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=36 | data = System.getenv("ADD");
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=41 | data = null;
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=45 | switch (7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=49 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=51 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=31, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=31, col=17 | 6
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=36, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=36, col=20 | System
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=36, col=20 | System.getenv("ADD")
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=36, col=34 | "ADD"
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=41, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=41, col=20 | null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=45, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=45, col=17 | 7
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=49, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=49, col=17 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=49, col=17 | data != null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=49, col=25 | null
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
                if (data != null)
                {
                    response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if`가 아니라 `response.addHeader(...)`(line 51)를 sink로 지정해야 함.


#### (2) Flow2 b2g1

- Source: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:139
- Sink: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:156

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=134 | switch (6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=139 | data = System.getenv("ADD");
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=144 | data = null;
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=148 | switch (8)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=156 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=158 | data = URLEncoder.encode(data, "UTF-8");
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=159 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=134, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=134, col=17 | 6
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=139, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=139, col=20 | System
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=139, col=20 | System.getenv("ADD")
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=139, col=34 | "ADD"
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=144, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=144, col=20 | null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=148, col=9 | switch(8)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=148, col=17 | 8
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=156, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=156, col=17 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=156, col=17 | data != null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=156, col=25 | null
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
                if (data != null)
                {
                    data = URLEncoder.encode(data, "UTF-8");
                    response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if` 다음의 `URLEncoder.encode(...)`와 `response.addHeader(...)`를 sink로 지정해야 함.


#### (3) Flow3 b2g2

- Source: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:175
- Sink: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:188

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=170 | switch (6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=175 | data = System.getenv("ADD");
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=180 | data = null;
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=184 | switch (7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=188 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=190 | data = URLEncoder.encode(data, "UTF-8");
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=191 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=170, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=170, col=17 | 6
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=175, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=175, col=20 | System
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=175, col=20 | System.getenv("ADD")
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=175, col=34 | "ADD"
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=180, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=180, col=20 | null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=184, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=184, col=17 | 7
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=188, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=188, col=17 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=188, col=17 | data != null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=188, col=25 | null
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
                if (data != null)
                {
                    data = URLEncoder.encode(data, "UTF-8");
                    response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if` 다음의 `URLEncoder.encode(...)`와 `response.addHeader(...)`를 sink로 지정해야 함.


#### (4) Flow4 g2b1

- Source: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:75
- Sink: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:83

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=66 | switch (5)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=71 | data = null;
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=75 | data = "foo";
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=79 | switch (7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=83 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=85 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=66, col=9 | switch(5)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=66, col=17 | 5
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=71, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=71, col=20 | null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=75, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=75, col=20 | "foo"
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=79, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=79, col=17 | 7
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=83, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=83, col=17 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=83, col=25 | null
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
                if (data != null)
                {
                    response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if`가 아니라 `response.addHeader(...)`(line 85)를 sink로 지정해야 함.


#### (5) Flow5 g2b2

- Source: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:104
- Sink: CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java:117

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=100 | switch (6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=104 | data = "foo";
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=109 | data = null;
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=113 | switch (7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=117 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=119 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=100, col=9 | switch(6)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=100, col=17 | 6
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=104, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=104, col=20 | "foo"
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=109, col=13 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=109, col=20 | null
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=113, col=9 | switch(7)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=113, col=17 | 7
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=117, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=117, col=17 | data
CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java | line=117, col=25 | null
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
                if (data != null)
                {
                    response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if`가 아니라 `response.addHeader(...)`(line 119)를 sink로 지정해야 함.


### [4] CWE-113 / Testcase 564

- Java 파일명: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java

#### (1) Flow1 b2b

- Source: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:53
- Sink: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:114

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=37 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=45 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=48 | socket = new Socket("host.example.org", 39544);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=51 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=53 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=105 | data = null;
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=108 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=110 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=112 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=114 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=34, col=49 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=37, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=37, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=45, col=17 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=48, col=21 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=48, col=30 | new Socket("host.example.org", 39544)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=48, col=41 | "host.example.org"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=48, col=61 | 39544
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50, col=63 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=50, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=51, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=51, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=51, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=53, col=21 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=53, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=53, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=105, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=105, col=20 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=108, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=108, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=110, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=110, col=17 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=110, col=17 | data != null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=110, col=25 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=112, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=112, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=112, col=48 | "lang"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=112, col=56 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=114, col=17 | response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=114, col=17 | response.addCookie(cookieSink)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=114, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (2) Flow2 b2g1

- Source: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:195
- Sink: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:262

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=179 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=187 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=190 | socket = new Socket("host.example.org", 39544);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=193 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=195 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=247 | data = null;
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=250 | if (IO.STATIC_FINAL_FALSE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=258 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260 | Cookie cookieSink = new Cookie("lang", URLEncoder.encode(data, "UTF-8"));
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=262 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=176, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=179, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=179, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=187, col=17 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=190, col=21 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=190, col=30 | new Socket("host.example.org", 39544)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=190, col=41 | "host.example.org"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=190, col=61 | 39544
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192, col=63 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=192, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=193, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=193, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=193, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=195, col=21 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=195, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=195, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=247, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=247, col=20 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=250, col=9 | if (IO.STATIC_FINAL_FALSE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=250, col=13 | IO.STATIC_FINAL_FALSE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=258, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=258, col=17 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=258, col=17 | data != null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=258, col=25 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=37 | new Cookie("lang", URLEncoder.encode(data, "UTF-8"))
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=48 | "lang"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=56 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=56 | URLEncoder
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=74 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=260, col=80 | "UTF-8"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=262, col=17 | response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=262, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


#### (3) Flow3 b2g2

- Source: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:288
- Sink: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:349

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=272 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=280 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=283 | socket = new Socket("host.example.org", 39544);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285 | readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8");
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=286 | readerBuffered = new BufferedReader(readerInputStream);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=288 | data = readerBuffered.readLine();
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=340 | data = null;
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=343 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=345 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347 | Cookie cookieSink = new Cookie("lang", URLEncoder.encode(data, "UTF-8"));
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=349 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=269, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=272, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=272, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=280, col=17 | try
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=283, col=21 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=283, col=30 | new Socket("host.example.org", 39544)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=283, col=41 | "host.example.org"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=283, col=61 | 39544
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285, col=21 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285, col=41 | new InputStreamReader(socket.getInputStream(), "UTF-8")
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285, col=63 | socket.getInputStream()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285, col=63 | socket
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=285, col=88 | "UTF-8"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=286, col=21 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=286, col=38 | new BufferedReader(readerInputStream)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=286, col=57 | readerInputStream
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=288, col=21 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=288, col=28 | readerBuffered.readLine()
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=288, col=28 | readerBuffered
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=340, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=340, col=20 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=343, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=343, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=345, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=345, col=17 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=345, col=17 | data != null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=345, col=25 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=37 | new Cookie("lang", URLEncoder.encode(data, "UTF-8"))
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=48 | "lang"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=56 | URLEncoder.encode(data, "UTF-8")
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=56 | URLEncoder
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=74 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=347, col=80 | "UTF-8"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=349, col=17 | response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=349, col=17 | response.addCookie(cookieSink)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=349, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (4) Flow4 g2b1

- Source: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:133
- Sink: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:143

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=123 | if (IO.STATIC_FINAL_FALSE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=127 | data = null;
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=133 | data = "foo";
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=137 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=139 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=141 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=143 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=120, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=123, col=9 | if (IO.STATIC_FINAL_FALSE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=123, col=13 | IO.STATIC_FINAL_FALSE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=127, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=127, col=20 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=133, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=133, col=20 | "foo"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=137, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=137, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=139, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=139, col=17 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=139, col=17 | data != null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=139, col=25 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=141, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=141, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=141, col=48 | "lang"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=141, col=56 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=143, col=17 | response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=143, col=17 | response.addCookie(cookieSink)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=143, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 적절
- 근거: source부터 sink까지 데이터 경로가 잘 추출됨.


#### (5) Flow5 g2b2

- Source: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:155
- Sink: CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java:170

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=152 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=155 | data = "foo";
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=161 | data = null;
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=164 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=166 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=168 | Cookie cookieSink = new Cookie("lang", data);
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=170 | response.addCookie(cookieSink);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=149, col=55 | HttpServletResponse response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=152, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=152, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=155, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=155, col=20 | "foo"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=161, col=13 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=161, col=20 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=164, col=9 | if (IO.STATIC_FINAL_TRUE)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=164, col=13 | IO.STATIC_FINAL_TRUE
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=166, col=13 | if (data != null)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=166, col=17 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=166, col=17 | data != null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=166, col=25 | null
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=168, col=24 | cookieSink
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=168, col=37 | new Cookie("lang", data)
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=168, col=48 | "lang"
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=168, col=56 | data
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=170, col=17 | response
CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java | line=170, col=36 | cookieSink
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink `response.addCookie(...)` 호출 노드가 실제 트레이스에서 누락됨(수신자·인자만 표기). 데이터는 sink 인자까지 도달하나 sink 연산 노드가 없음.


### [5] CWE-113 / Testcase 502

- Java 파일명: CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java

#### (1) Flow3 g2b

- Source: CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java:127
- Sink: CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java:114

**예상 트레이스**

```text
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=127 | data = "foo";
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=129 | goodG2BSink(data , request, response );
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=110 | private void goodG2BSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=114 | if (data != null)
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=116 | response.addHeader("Location", "/author.jsp?lang=" + data);
```

**실제 트레이스**

```text
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=110, col=30 | String data
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=114, col=9 | if (data != null)
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=114, col=13 | data
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=114, col=13 | data != null
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=114, col=21 | null
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=127, col=9 | data
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=127, col=16 | "foo"
CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java | line=129, col=21 | data
```

**비교 결과**

- 추출 범위: 부족
- 근거: sink이 `if (data != null)` 가드로 지정됨(`POTENTIAL FLAW` 주석이 실제 위험 지점이 아닌 가드 위에 있음) → 슬라이스가 가드에서 멈춰 실제 sink 라인이 트레이스에 아예 없음.
    ```java
            if (data != null)
            {
                response.addHeader("Location", "/author.jsp?lang=" + data);
    ```
    `if`가 아니라 `response.addHeader(...)`(line 116)를 sink로 지정해야 함.


### [6] CWE-789 / Testcase 1044

- Java 파일명: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:50
- Sink: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:70

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함. `POTENTIAL FLAW` 주석 다음 줄의 여는 괄호 `{`를 source로 지정하여 시작점이 없음.
    ```java
                /* POTENTIAL FLAW: Read data from a querystring using getParameter() */
                {
                    String stringNumber = request.getParameter("name");
                    try
                    {
    ```
    블록 여는 `{`(line 50)가 아니라 내부의 실제 오염 대입문을 source로 지정해야 함.


#### (2) Flow2 g2b1

- Source: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:88
- Sink: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:93

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=78 | if (privateReturnsFalse())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=82 | data = 0;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=84 | else
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=88 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=93 | HashMap intHashMap = new HashMap(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=75, col=5 | this
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=78, col=9 | if (this.privateReturnsFalse())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=78, col=13 | this.privateReturnsFalse()
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=78, col=13 | this
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=82, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=82, col=20 | 0
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=88, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=88, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=93, col=17 | intHashMap
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=93, col=30 | new HashMap(data)
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=93, col=42 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나 else 라인 자체는 추출 안 됨. 그 외 적절함.


#### (3) Flow3 g2b2

- Source: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:104
- Sink: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java:114

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=101 | if (privateReturnsTrue())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=104 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=106 | else
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=110 | data = 0;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=114 | HashMap intHashMap = new HashMap(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=98, col=5 | this
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=101, col=9 | if (this.privateReturnsTrue())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=101, col=13 | this.privateReturnsTrue()
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=101, col=13 | this
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=104, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=104, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=110, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=110, col=20 | 0
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=114, col=17 | intHashMap
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=114, col=30 | new HashMap(data)
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java | line=114, col=42 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나 else 라인 자체는 추출 안 됨. 그 외 적절함.


### [7] CWE-789 / Testcase 1011

- Java 파일명: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java:36
- Sink: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java:57

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함. `POTENTIAL FLAW` 주석 다음 줄의 여는 괄호 `{`를 source로 지정하여 시작점이 없음.
    ```java
                /* POTENTIAL FLAW: Read data from a querystring using getParameter() */
                {
                    String stringNumber = request.getParameter("name");
                    try
                    {
    ```
    블록 여는 `{`(line 36)가 아니라 내부의 실제 오염 대입문을 source로 지정해야 함.


#### (2) Flow2 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java:69
- Sink: CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java:80

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=66 | if (IO.staticReturnsTrueOrFalse())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=69 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=71 | else
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=75 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=80 | ArrayList intArrayList = new ArrayList(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=66, col=9 | if (IO.staticReturnsTrueOrFalse())
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=66, col=13 | IO.staticReturnsTrueOrFalse()
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=66, col=13 | IO
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=69, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=69, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=75, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=75, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=80, col=19 | intArrayList
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=80, col=34 | new ArrayList(data)
CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java | line=80, col=48 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나 else 라인 자체는 추출 안 됨. 그 외 적절함.


### [8] CWE-789 / Testcase 187

- Java 파일명: CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java

#### (1) Flow2 g2b1

- Source: CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java:138
- Sink: CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java:143

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=128 | if (false)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=132 | data = 0;
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=134 | else
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=138 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=143 | HashSet intHashSet = new HashSet(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=128, col=9 | if (false)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=128, col=13 | false
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=132, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=132, col=20 | 0
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=138, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=138, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=143, col=17 | intHashSet
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=143, col=30 | new HashSet(data)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=143, col=42 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나 else 라인 자체는 추출 안 됨. 그 외 적절함.


#### (2) Flow3 g2b2

- Source: CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java:154
- Sink: CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java:164

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=151 | if (true)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=154 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=156 | else
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=160 | data = 0;
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=164 | HashSet intHashSet = new HashSet(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=151, col=9 | if (true)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=151, col=13 | true
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=154, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=154, col=20 | 2
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=160, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=160, col=20 | 0
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=164, col=17 | intHashSet
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=164, col=30 | new HashSet(data)
CWE789_Uncontrolled_Mem_Alloc__File_HashSet_02.java | line=164, col=42 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: if-else의 else 내부 코드는 추출되었으나 else 라인 자체는 추출 안 됨. 그 외 적절함.


### [9] CWE-789 / Testcase 1565

- Java 파일명:
    - CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java
    - CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java:31
- Sink: CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java:30

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source와 sink 위치는 정상이나, static field를 통한 값 전달을 joern이 처리하지 못함(확인됨)


#### (2) Flow2 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java:46
- Sink: CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java:40

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java | line=46 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java | line=48 | (new CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b()).goodG2BSink();

CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=37 | int data = CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.data;
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=40 | HashSet intHashSet = new HashSet(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java | line=46, col=16 | 2

CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=37, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=37, col=20 | CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.data
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=40, col=17 | intHashSet
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=40, col=30 | new HashSet(data)
CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68b.java | line=40, col=42 | data
```

**비교 결과**

- 추출 범위: 적절
- 근거: 정적 멤버를 통한 클래스 간 전달까지 잘 추출됨. Sink 호출 함수명은 미추출되나 인자/매개변수는 포함됨.


### [10] CWE-789 / Testcase 97

- Java 파일명: CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java

#### (1) Flow1 b2b

- Source: CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java:49
- Sink: CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java:36

**실제 트레이스**

```text
No data-flow path found.
```

**비교 결과**

- 추출 범위: 추출 실패
- 근거: source를 잘못 지정함. `POTENTIAL FLAW` 주석 다음 줄의 여는 괄호 `{`를 source로 지정하여 시작점이 없음.
    ```java
            /* POTENTIAL FLAW: Read data from an environment variable */
            {
                String stringNumber = System.getenv("ADD");
                if (stringNumber != null) // avoid NPD incidental warnings
                {
    ```
    블록 여는 `{`(line 49)가 아니라 내부의 실제 오염 대입문을 source로 지정해야 함.


#### (2) Flow2 g2b

- Source: CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java:88
- Sink: CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java:78

**예상 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=88 | data = 2;
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=90 | dataGoodG2B = data;
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=91 | goodG2BSink();
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=75 | int data = dataGoodG2B;
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=78 | HashSet intHashSet = new HashSet(data);
```

**실제 트레이스**

```text
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=73, col=5 | this
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=75, col=13 | data
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=75, col=20 | this.dataGoodG2B
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=78, col=-1 | new HashSet(data)
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=78, col=17 | intHashSet
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=78, col=30 | new HashSet(data)
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=78, col=42 | data
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=83, col=5 | this
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=88, col=9 | data
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=88, col=16 | 2
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=90, col=9 | this.dataGoodG2B
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=90, col=23 | data
CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java | line=91, col=9 | this
```

**비교 결과**

- 추출 범위: 적절
- 근거: private 멤버를 통한 메서드 간 전달까지 잘 추출됨. 그 외 적절함.


## 요약

- 정상적으로 추출된 flow 수 : 15개 (CWE-113 8개 + CWE-789 7개)

- 부족하게 추출된 flow 수 : 13개 (모두 CWE-113)
    - sink 연산 노드(`setHeader`/`addCookie`)가 트레이스에 없음 : 7개 — 데이터는 sink 인자까지 도달하나 sink 호출 노드가 누락됨. 예를 들어 'response.setHeader("Location", "/author.jsp?lang=" + data);'가 sink 인데 함수 호출의 setHeader 키워드가 추출되지 않음
        - CWE113_HTTP_Response_Splitting__listen_tcp_setHeaderServlet_15.java : flow4
        - CWE113_HTTP_Response_Splitting__PropertiesFile_addCookieServlet_07.java : flow1, flow2, flow4, flow5
        - CWE113_HTTP_Response_Splitting__connect_tcp_addCookieServlet_09.java : flow2, flow5
    - sink가 `if (data != null)` 로 지정돼 실제 sink 라인이 통째로 누락 : 6개 — sink 재지정 필요. 예를 들어 'if (data != null)' 아래의 if문 내부 블럭의 'response.addHeader("Location", "/author.jsp?lang=" + data);'가 취약한 sink인데 data의 null을 체크하는 코드가 sink로 지정됨 
        - CWE113_HTTP_Response_Splitting__Environment_addHeaderServlet_15.java : flow1, flow2, flow3, flow4, flow5
        - CWE113_HTTP_Response_Splitting__URLConnection_addHeaderServlet_41.java : flow3

- 추출 실패한 flow 수 : 4개 (모두 CWE-789)
    - source를 `POTENTIAL FLAW` 다음 줄의 `{` 블록 괄호로 잘못 지정 : 3개
        - CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_HashMap_08.java : flow1
        - CWE789_Uncontrolled_Mem_Alloc__getParameter_Servlet_ArrayList_12.java : flow1
        - CWE789_Uncontrolled_Mem_Alloc__Environment_HashSet_45.java : flow1
    - source/sink는 정상이나 joern이 static 필드를 통한 값 전달을 처리하지 못해 경로 미검출 : 1개
        - CWE789_Uncontrolled_Mem_Alloc__random_HashSet_68a.java / 68b.java : flow1
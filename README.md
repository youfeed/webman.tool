# Youloge.Tool Webman 辅助函数插件 

### 项目介绍 

>  封装一些常用函数，方便使用：函数名称注意有没有与你的项目发生冲突，更要注意函数所依赖的包依赖，如果依赖的包没有安装，函数将无法使用


### 项目地址

[Github Youloge.Tool](https://github.com/youfeed/webman.tool) Star我 `我们一起做大做强`

- 0.0.1 初始项目

### 安装

```php
composer require youloge/tool
```
> 插件已经 引入了以下助手函数 `以下函数名不要重复`

> 插件已经 引入了以下助手函数 `以下函数名不要重复`


### `ini($keys,$default)` 读取*.env* 配置文件

> 以下保留字不得用作 ini 文件的键：null、yes、no、true、false、on、off、none。此外，密钥中不得使用以下保留字符：{}|&~!()^"。

- `$keys` 配置文件`.env`键值使用`.`分割 例如`MYSQL.HOST`
- `$default` 可选参数 默认值 ''

`.env`配置文件 使用以下格式

```env
[MYSQL]
HOST=127.0.0.1
PASSWORD=这里写密码
...
[REDIS]
HOST=127.0.0.1
PORT=6379
PASSWORD=这里写密码
```
> 使用方法
```php
ini('MYSQL.HOST','127.0.0.1'); // 读取配置文件 如果未找到则返回 `127.0.0.1`
```

### `shuffle_base32($len)` 打乱字符串

- $len 可选长度 默认4

> 打乱字符`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`

```php
shuffle_base32(4) // 最大长度 32 
```

### `runRedis($method,$params)` 

- `$method` redis 方法
- `$params` redis 参数 数组类型

> 使用默认配置文件 `redis` 读取数据

```php
runRedis('HGET',["wallet",'key1']) // string key1 的值
```
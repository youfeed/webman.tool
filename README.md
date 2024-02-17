# Youloge.Tool Webman 辅助函数插件 

### 项目介绍 

> 使用本插件。以下函数不能和自己的项目发生函数名称冲突


### 项目地址

[Github Youloge.Tool](https://github.com/youfeed/webman.tool) Star我 `我们一起做大做强`

- 0.0.1 初始项目

### 安装

```php
composer require youloge/tool
```
> 插件已经 引入了以下助手函数 `以下函数名不要重复`

> 插件已经 引入了以下助手函数 `以下函数名不要重复`


### `ini('NAME.NAME','default')` 读取*.env* 配置文件

> 以下保留字不得用作 ini 文件的键：null、yes、no、true、false、on、off、none。此外，密钥中不得使用以下保留字符：{}|&~!()^"。

- `NAME.NAME` 配置文件`.env` 键值
- `default(可选值)` 默认值

`.env`配置文件 使用以下格式

```env
[MYSQL]
HOST=127.0.0.1
PASSWORD=这里写密码
DATABASE=这里写数据库名
PORT=3306
USER=这里写用户名

[REDIS]
HOST=127.0.0.1
PORT=6379
PASSWORD=这里写密码
```
> 使用方法
```php
ini('MYSQL.HOST','127.0.0.1'); // 读取配置文件 如果未找到则返回 `127.0.0.1`
```

### `shuffle_base32(4)` 打乱字符串

> 打乱字符`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`

```php
shuffle_base32(4) // 最大长度 32 
```
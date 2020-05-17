# 简介

基于 flask 的博客 demo，是本人本学期的大作业😂

平时在使用 hexo 的静态博客，受次启发想开发一个博客

由于 web 基础还不好，css 非常生疏，布局问题非常大，且是从零开始开发的，功能目前还很少，之后会再更新。

开发步骤基本就是：

- 看官方文档，把里面的例子实现
- 再照着已实现的功能加需求
- 找博客和其他 flask 项目进行参考，添加功能

![](https://gitee.com/jzhmcoo1/jzhmcoo1picrepo/raw/master/img/blogoverview.jpg)

# TODO：


- [x] 登录，注销，注册功能
- [x] 个人资料页
- [x] 支持 markdown 写作
- [ ] 评论，点赞
- [ ] 目录功能
- [ ] 上传 md 文件
- [ ] 更美观的个人资料页
- [ ] 更改 md 渲染主题
- [ ] More

# 安装

```bash
$ git clone https://github.com/jzhmcoo1/MyBlog.git
$ cd MyBlog
```

On MacOS:

```bash
# create a virtualenv and activate it
$ python3 -m venv venv
$ . venv/bin/activate
```

On Windows cmd:

```
$ py -3 -m venv venv
$ venv\Scripts\activate.bat
```



# 本地运行

```bash
$ export FLASK_APP=flaskr
$ export FLASK_ENV=development
$ flask init-db
$ flask run
```

Or on Windows cmd:

```bash
> set FLASK_APP=flaskr
> set FLASK_ENV=development
> flask init-db
> flask run
```

 Open http://127.0.0.1:5000 in your browser.



# 参考文档与博客：

- [欢迎来到 Flask 的世界 — Flask 中文文档（ 1.1.1 ）](https://dormousehole.readthedocs.io/en/latest/index.html)
- [Template Designer Documentation — Jinja Documentation (2.11.x)](https://jinja.palletsprojects.com/en/2.11.x/templates/)
- [Blackyukun/quiet: 支持上传 markdown 文件生成 html 的 flask 静态博客](https://github.com/Blackyukun/quiet)
- [Sitemap — Python-Markdown 3.2.2 documentation](https://python-markdown.github.io/sitemap.html)
- [基于flask的静态博客 - 后端 - 掘金](https://juejin.im/entry/5a8d8776f265da4e8b2feac7)


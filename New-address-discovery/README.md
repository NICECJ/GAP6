# 激活虚拟环境

```
source venv/bin/activate
```

# 确认 BGP 前缀文件

input/BGP_prefixes.txt 类似：

```
2001:db8::/32
2400:3200::/32
2a00:1450::/32
```

# 运行协议生成器

```
python llm_protocol_builder.py
```

这个脚本会：

- 读取 ipv6_probes/

- 调用大模型

- 生成探测代码

- 写入 protocols/

# 编译探测程序

```
make
``` 

# 运行探测程序

```
sudo ./run.sh ack_rst
```

# 输出结果

结果会保存在 output/ 目录下，包含：

- 生成的协议插件代码

- 运行日志


# @goodandready-private/dsh-approval-gate

Host-only 安全门：在工具正文运行前拦截危险的 bash 调用以及对密钥文件的写入。操作者使用已有的确认词 `делай`。

完整覆盖表、限制和配置见 [README.md](README.md)。

安装（GitHub Packages 私有包）：

```sh
dsh plugin --profile web add @goodandready-private/dsh-approval-gate
```

# @goodandready-private/dsh-approval-gate

Host-only 安全门：在工具正文运行前拦截危险的 bash 调用以及对密钥文件的写入。操作者使用已有的确认词 `делай`。

完整覆盖表、限制和配置见 [README.md](README.md)。

安装（GitHub Packages 私有包）：

```sh
dsh plugin --profile web add @goodandready-private/dsh-approval-gate
```

## v0.1.3 变更

本节说明 0.1.3 中的行为：扩展有界 shell 语法分析，并在无法确定语法或执行目标时请求 DSH 审批，同时保留对已识别破坏性操作和受保护文件写入的拒绝规则。

shell 分析器现在支持命令替换、反引号、进程替换、常见重定向（包括 2> 和 &>）、管道和 here-document，并递归检查嵌套 shell 命令及可执行展开。普通安全读取可以通过。展开的 Authorization 请求头需要审批，因为 curl 会把凭据作为进程参数接收。本包暂不提供安全的 Gitea API 助手；请勿将令牌放入命令行参数。

语言服务是可选的；如果服务不可用，安全钩子仍会使用英文回退消息运行。

已识别的破坏性操作和受保护文件写入仍会被拒绝，包括递归 rm、进程信号、服务停止或重启、破坏性 SQL、受保护文件写入、git reset --hard、强制 git clean、mkfs、写入设备的 dd，以及将下载内容传给 shell。

未闭合或不支持的语法、动态命令名或重定向目标，以及无法检查内容的脚本文件，会通过 DSH 请求审批。审批不可用或配置为 approval=never 时，DSH 会拒绝请求。本插件不会读取脚本文件，也不实现独立审批口令。提示会显示规则名称和脱敏后的命令片段。这是有界 shell 分析器，并非完整 Bash 语法解析器。

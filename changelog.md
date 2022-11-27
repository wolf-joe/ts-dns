# 未来版本

- [ ] DoT/GFWList域名解析自闭环
- [ ] 支持http接口管理
- [ ] 降低gfwlist的匹配优先级

# v1.0.0

- [x] 从配置中移除`query_log`、`gfwlist`、`gfwlist_b64`项
- [x] 增加`gfwlist`模块，并支持定期拉取最新文件
- [x] 移除针对`dirty`、`clean`组的特殊逻辑
- [x] 支持为特定组指定`gfwlist`匹配策略、兜底匹配策略
- [x] 收到`SIGNUP`信号时重载配置文件
- [x] 支持非CNIP转发到指定组策略
- [ ] 完全重构代码
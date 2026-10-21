# 双层鳕鱼堡的 Hexo 博客

卡通餐盘、双层鳕鱼堡头像、奶油黄与红色点缀，配合视差背景和半透明磨砂玻璃。完整源码、38 篇题解与学习记录、17 个 GitHub Stars 快照都在此工程中。文章支持方向、来源和关键词组合筛选。

这是 GitHub Pages 专用发布源，目标地址为 `https://ken12376.github.io/`。首次部署步骤见 [部署说明](docs/github-pages.md)。

## 本地使用

需要 Node.js 20.19 或更新版本。本次实际使用 Node.js 24.18.1、Hexo 8.1.2。

```powershell
npm ci
npm start
```

打开 http://127.0.0.1:4000 。运行 `npm run build` 生成 `dist/` 静态站点，部署时上传该目录的内容即可。不要直接双击 index.html，因为页面使用站点根路径。

## 写新题解

将 Markdown 放入 `source/_posts/` 对应方向文件夹，例如 `reverse/my-challenge.md`：

```yaml
---
title: 我的新题解
date: 2026-10-21
categories: Reverse
tags: [VM, PE]
excerpt: 用一两句话记录题目的关键思路。
slug: my-challenge
---
```

之后正常编写 Markdown。分类支持 `Reverse`、`Pwn`、`Web`、`Crypto`、`Misc`、`Forensics`；目录由标题自动生成。代码围栏里的模板花括号由 Hexo 保护，无需给整篇文章包 raw 标签。本站的 Markdown 渲染采用 Hexo 默认策略，只构建本人审阅过的内容。

## 更新星标

```powershell
npm run sync:stars
npm run build
```

从 `_config.yml` 的 `github_username` 读取账号。当前为经连接账号确认的 `Ken12376`。使用 GitHub 公开 API，无需密钥，按最近收藏排序，支持分页；请求失败时保留旧快照。星标页面展示的是构建时快照，页面搜索和语言筛选均在浏览器本地执行。

## 内容与素材

- 题解：HDCTF 19 篇、0xGame 16 篇、散题 2 篇，共 37 篇。堆染钟楼原文仅得到半旗，已明确标为「未完成记录」。完整目录见 `docs/content-index.md`。
- 学习记录：Sec招新目录最新的 `25-re-鳕鱼堡-1018.md`，修改时间为 2026-10-18 16:54:41，归入 Reverse。附带 10 张已核验本地图；原文两张独立远程图无法获取，保留说明与链接。
- 已删除副本中的本机路径、比赛服务器地址与固定认证材料；原始文章未修改。CTF flag 和题目公开数学参数保留。
- 原文未注明时间时使用源文件修改日期，并在对应文章注明。赛题附件未随博客打包，正文列出所需材料；题目合集不重复导入。UPX 原文署名「海鸥」已保留。
- 头像：用户提供的原始 `source/assets/burger.jpg`，已核对与原图一致。
- 餐盘背景：内置 imagegen 生成，文件为 `source/assets/diner-scene.png`；提示词见 `docs/image-prompt.md`。
- 主题：`themes/codfish/`；页面生成与轻量助手：`scripts/blog.js`。
- 发布配置：`.github/workflows/pages.yml`；推送 `main` 后由 GitHub Actions 构建并发布。此副本不包含 Sites 托管标识。

## 验证与依赖说明

已实际构建，检查文章正文、代码、配图与目录，测试方向和来源组合筛选、空结果恢复、Stars 语言筛选与代码复制，并检查桌面和手机断点。

当前 npm audit 报告 7 项 high、2 项 moderate，根源为构建依赖 `braces` 和 `sprintf-js` 的两项上游公告，检查时尚无补丁版本。保留 Hexo 8，未执行会降级框架的 `npm audit fix --force`。线上仅部署静态文件，这些 Node 包不在访客浏览器或服务器请求路径中运行。后续更新依赖时应重新检查。

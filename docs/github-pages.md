# GitHub Pages 部署

本目录是独立的 GitHub Pages 发布源，目标仓库为 `Ken12376/Ken12376.github.io`，目标网址为 `https://ken12376.github.io/`。现有 Sites 站点可继续使用。

## 已配置

- 根站点路径 `/`，静态输出目录 `dist/`。
- GitHub Actions 使用 Node 24 执行 `npm ci` 和 `npm run build`，再部署生成的静态文件。
- 默认分支为 `main`；推送新文章后自动构建，也可在 Actions 页面手动运行。
- 使用 GitHub 自动提供的 `GITHUB_TOKEN`，无需额外创建或保存个人访问令牌。
- 没有复制 Sites 的托管标识、原 Git 历史、依赖目录或旧构建产物。

## 首次启用

1. 在 GitHub 账号 `Ken12376` 下创建公开仓库 `Ken12376.github.io`。
2. 上传本目录中的源码，包括隐藏的 `.github/workflows/pages.yml`。
3. 在仓库 Settings → Pages → Build and deployment 中，将 Source 设为 GitHub Actions。
4. 查看 Actions 中的部署任务，成功后访问目标网址。

仓库创建与 Pages 设置需要当前账号的写入权限。目标网址只有在部署任务成功且返回博客正文后，才能视为已上线。

## 本地构建

```powershell
npm ci
npm run build
npm start
```

更新星标时，先运行 `npm run sync:stars`，然后提交新的快照。部署本身使用现有快照，不依赖额外的 GitHub API 请求。

参考：[Hexo 官方教程](https://hexo.io/docs/github-pages)、[GitHub Actions 部署说明](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)。

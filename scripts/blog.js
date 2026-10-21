'use strict';

const directions = [
  { name: 'Reverse', label: '逆向工程', icon: 'code', note: '拆开程序，读懂逻辑', mark: '</>' },
  { name: 'Pwn', label: '二进制安全', icon: 'terminal', note: '在边界处寻找可能', mark: '>_' },
  { name: 'Web', label: 'Web 安全', icon: 'globe', note: '请求背后的另一面', mark: '{ }' },
  { name: 'Crypto', label: '密码学', icon: 'key', note: '把数学变成钥匙', mark: 'a≡b' },
  { name: 'Misc', label: '杂项探索', icon: 'spark', note: '好奇心没有固定形状', mark: '✳' },
  { name: 'Forensics', label: '数字取证', icon: 'search', note: '让每一条线索说话', mark: '010' }
];
const CHARACTERS_PER_MINUTE = 500;
const iconPaths = {
  arrow: '<path d="M5 12h14m-6-6 6 6-6 6"/>',
  diagonal: '<path d="M6 18 18 6M6 6h12v12"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  code: '<path d="m7 7-5 5 5 5m10-10 5 5-5 5m-4-14-2 18"/>',
  terminal: '<path d="m5 6 6 6-6 6m8 0h6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-3-3 3-3m-6 0 3-3"/>',
  spark: '<path d="m12 2 2.5 7.5L22 12l-7.5 2.5L12 22l-2.5-7.5L2 12l7.5-2.5Z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  up: '<path d="m5 14 7-7 7 7"/>',
  github: '<path d="M9 19c-4 1-4-2-6-2m12 4v-3.4c0-1 .1-1.5-.5-2.1 3.3-.4 6.5-1.5 6.5-7.1A5.5 5.5 0 0 0 19.5 4c.2-1 .2-2-.1-3 0 0-1.2-.4-4 1.5a15 15 0 0 0-7 0C5.6.6 4.4 1 4.4 1c-.3 1-.3 2-.1 3A5.5 5.5 0 0 0 3 8.4c0 5.6 3.2 6.7 6.5 7.1-.6.6-.6 1.2-.5 2.1V21"/>'
};

hexo.extend.helper.register('icon', name => `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name] || iconPaths.code}</svg>`);
hexo.extend.helper.register('blog', () => {
  const posts = hexo.locals.get('posts').sort('-date').toArray();
  return { posts, directions: directions.map(direction => ({ ...direction, count: posts.filter(post => post.categories.toArray().some(category => category.name === direction.name)).length })) };
});
hexo.extend.helper.register('direction_for', post => directions.find(direction => post.categories.toArray().some(category => category.name === direction.name)) || directions[0]);
hexo.extend.helper.register('reading_minutes', post => Math.max(1, Math.ceil(post.content.replace(/<[^>]+>/g, '').length / CHARACTERS_PER_MINUTE)));
hexo.extend.generator.register('blog-pages', () => [
  { path: 'index.html', layout: 'index', data: { pageKind: 'home' } },
  ...['writeups', 'about', 'archives', 'categories'].map(name => ({ path: `${name}/index.html`, layout: name === 'archives' || name === 'categories' ? 'writeups' : name, data: { pageKind: name, title: { writeups: '题解菜单', about: '关于我', archives: '文章归档', categories: '方向分类' }[name] } })),
  ...directions.map(direction => ({ path: `categories/${direction.name}/index.html`, layout: 'writeups', data: { pageKind: 'category', title: `${direction.label} · ${direction.name}`, categoryName: direction.name } })),
  { path: '404.html', layout: '404', data: { pageKind: 'not-found', title: '这一层还没有内容' } }
]);

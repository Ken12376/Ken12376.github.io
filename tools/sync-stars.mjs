import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';

const projectRoot = new URL('../', import.meta.url);
const snapshotPath = new URL('source/_data/stars.json', projectRoot);
const temporaryPath = new URL(`source/_data/stars.${process.pid}.tmp`, projectRoot);
const pageSize = 100;
const requestTimeoutMs = 30_000;
const maximumUsernameLength = 39;

function publicRepository(repository) {
  const strings = ['name', 'full_name', 'html_url', 'updated_at'];
  const counts = ['stargazers_count', 'forks_count'];
  if (repository?.private !== false ||
      strings.some(field => typeof repository[field] !== 'string' || !repository[field]) ||
      typeof repository.owner?.login !== 'string' || !repository.owner.login ||
      counts.some(field => !Number.isSafeInteger(repository[field]) || repository[field] < 0) ||
      !['description', 'language'].every(field => repository[field] === null || typeof repository[field] === 'string') ||
      !Array.isArray(repository.topics) || repository.topics.some(topic => typeof topic !== 'string') ||
      !Number.isFinite(Date.parse(repository.updated_at))) {
    throw new Error('GitHub returned an invalid public repository record.');
  }
  const expectedUrl = `https://github.com/${repository.owner.login}/${repository.name}`;
  if (repository.full_name !== `${repository.owner.login}/${repository.name}` || repository.html_url !== expectedUrl) {
    throw new Error('GitHub returned an inconsistent repository identity.');
  }
  return {
    name: repository.name,
    full_name: repository.full_name,
    owner: repository.owner.login,
    description: repository.description,
    url: repository.html_url,
    language: repository.language,
    stars: repository.stargazers_count,
    forks: repository.forks_count,
    topics: repository.topics,
    updated_at: repository.updated_at
  };
}

async function fetchStars(username) {
  const repositories = [];
  for (let page = 1; ; page++) {
    const endpoint = new URL(`https://api.github.com/users/${username}/starred`);
    endpoint.search = new URLSearchParams({ per_page: String(pageSize), page: String(page), sort: 'created', direction: 'desc' });
    const response = await fetch(endpoint, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'codfish-blog-stars' },
      signal: AbortSignal.timeout(requestTimeoutMs)
    });
    if (!response.ok) throw new Error(`GitHub Stars request failed on page ${page}: HTTP ${response.status}.`);
    const batch = await response.json();
    if (!Array.isArray(batch)) throw new Error(`GitHub returned an invalid page ${page}.`);
    repositories.push(...batch.map(publicRepository));
    if (batch.length < pageSize) return repositories;
  }
}

async function synchronize() {
  const configuration = await readFile(new URL('_config.yml', projectRoot), 'utf8');
  const setting = configuration.match(/^github_username:\s*([^\r\n]*)/m)?.[1];
  const username = setting === undefined ? 'Ken12376' : setting.replace(/\s+#.*$/, '').trim().replace(/^(['"])(.*)\1$/, '$2');
  if (username.length > maximumUsernameLength || !/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(username)) {
    throw new Error('Invalid github_username in _config.yml.');
  }
  const repositories = await fetchStars(username);
  if (new Set(repositories.map(repository => repository.full_name)).size !== repositories.length) {
    throw new Error('GitHub returned duplicate repositories; retry the synchronization.');
  }
  const snapshot = { username, updated_at: new Date().toISOString(), total: repositories.length, repositories };
  await mkdir(new URL('source/_data/', projectRoot), { recursive: true });
  try {
    await writeFile(temporaryPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
    await rename(temporaryPath, snapshotPath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
  console.log(`Saved ${snapshot.total} public starred repositories for ${username}.`);
}

synchronize().catch(error => {
  console.error(`Stars synchronization failed; existing snapshot preserved. ${error.message}`);
  process.exitCode = 1;
});

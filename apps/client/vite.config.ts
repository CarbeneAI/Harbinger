import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { readNetworkPolicy } from '../server/src/network-policy'

export default defineConfig(({ mode }) => {
  // Read selected server-side settings without exposing the .env contents to
  // browser code. Explicit shell values take precedence over the root .env.
  const env = { ...loadEnv(mode, fileURLToPath(new URL('../..', import.meta.url)), ''), ...process.env }
  const policy = readNetworkPolicy(env)
  const host = env.HARBINGER_CLIENT_HOST || '127.0.0.1'
  const allowedHosts = [...policy.allowedHosts]
  const apiHost = policy.hostname === '0.0.0.0' ? '127.0.0.1' : policy.hostname === '::' ? '::1' : policy.hostname
  const apiAuthority = apiHost.includes(':') ? `[${apiHost}]` : apiHost
  return {
    plugins: [vue()],
    server: {
      host,
      port: Number(env.CLIENT_PORT || '5174'),
      allowedHosts,
      proxy: {
        '^/api(?:/|$)': {
          target: `http://${apiAuthority}:${env.PORT || '4001'}`,
          changeOrigin: true,
          rewrite: path => path.replace(/^\/api(?=\/|$)/, '') || '/',
        },
      },
    },
    preview: { host, allowedHosts },
  }
})

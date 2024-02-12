				import worker, * as OTHER_EXPORTS from "/Users/vigneshks/Documents/GitHub/d1-lucia/.wrangler/tmp/pages-P4esJS/jqb86a0vj6.js";
				import * as __MIDDLEWARE_0__ from "/opt/homebrew/Cellar/cloudflare-wrangler2/3.28.1/libexec/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts";
				const envWrappers = [__MIDDLEWARE_0__.wrap].filter(Boolean);
				const facade = {
					...worker,
					envWrappers,
					middleware: [
						__MIDDLEWARE_0__.default,
            ...(worker.middleware ? worker.middleware : []),
					].filter(Boolean)
				}
				export * from "/Users/vigneshks/Documents/GitHub/d1-lucia/.wrangler/tmp/pages-P4esJS/jqb86a0vj6.js";

				const maskDurableObjectDefinition = (cls) =>
					class extends cls {
						constructor(state, env) {
							let wrappedEnv = env
							for (const wrapFn of envWrappers) {
								wrappedEnv = wrapFn(wrappedEnv)
							}
							super(state, wrappedEnv);
						}
					};
				

				export default facade;
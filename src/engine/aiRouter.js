/**
 * @fileoverview Gestor de Motores de IA y Escudo Anti-Denegación de Billetera (BYOK).
 * Soporta Modo Unificado (todos los Guardianes comparten modelo) y Modo Especializado
 * (cada Guardián usa el modelo óptimo para su rol), con fallback automático al
 * Motor Polimórfico Local ($0.00) para proteger el presupuesto ante ataques masivos.
 */

export const GUARDIAN_IDS = ['SENTINEL', 'WEAVER', 'MIRAGE', 'CHRONICLER'];

export const PROVIDER_CATALOG = {
  'polymorphic-local': {
    label: 'Motor Polimórfico Autónomo ($0.00)',
    requiresApiKey: false,
    supportsCustomModel: false,
    models: ['deterministic-swarm-v1'],
    costPerCallEstimateUsd: 0
  },
  openrouter: {
    label: 'OpenRouter API (300+ Modelos & :free)',
    requiresApiKey: true,
    supportsCustomModel: true,
    models: [
      'deepseek/deepseek-r1:free',
      'deepseek/deepseek-chat-v3-0324:free',
      'meta-llama/llama-3.3-70b-instruct:free',
      'google/gemini-2.5-pro',
      'google/gemini-2.5-flash',
      'anthropic/claude-sonnet-4-5',
      'anthropic/claude-haiku-4-5',
      'openai/gpt-4.1',
      'openai/gpt-4.1-mini',
      'qwen/qwen-2.5-coder-32b-instruct'
    ],
    costPerCallEstimateUsd: 0.0005
  },
  gemini: {
    label: 'Google Gemini API',
    requiresApiKey: true,
    supportsCustomModel: false,
    models: ['gemini-2.5-flash-lite', 'gemini-2.5-flash', 'gemini-2.5-pro'],
    costPerCallEstimateUsd: 0.0008
  },
  openai: {
    label: 'OpenAI API',
    requiresApiKey: true,
    supportsCustomModel: false,
    models: ['gpt-4.1-mini', 'gpt-4.1'],
    costPerCallEstimateUsd: 0.0015
  },
  anthropic: {
    label: 'Anthropic Claude API',
    requiresApiKey: true,
    supportsCustomModel: false,
    models: ['claude-haiku-4-5', 'claude-sonnet-4-5'],
    costPerCallEstimateUsd: 0.0022
  },
  deepseek: {
    label: 'DeepSeek API',
    requiresApiKey: true,
    supportsCustomModel: false,
    models: ['deepseek-chat', 'deepseek-reasoner'],
    costPerCallEstimateUsd: 0.0004
  },
  groq: {
    label: 'Groq Cloud API (Ultra Rápida)',
    requiresApiKey: true,
    supportsCustomModel: false,
    models: ['llama-3.1-8b-instant', 'llama-3.3-70b-versatile'],
    costPerCallEstimateUsd: 0.0003
  },
  ollama: {
    label: 'Ollama Local (Autoalojado $0.00)',
    requiresApiKey: false,
    supportsCustomModel: true,
    models: ['llama3.2:latest', 'qwen2.5-coder:latest'],
    costPerCallEstimateUsd: 0
  }
};

const DEFAULT_ASSIGNMENTS = {
  SENTINEL: { provider: 'polymorphic-local', model: 'deterministic-swarm-v1' },
  WEAVER: { provider: 'polymorphic-local', model: 'deterministic-swarm-v1' },
  MIRAGE: { provider: 'polymorphic-local', model: 'deterministic-swarm-v1' },
  CHRONICLER: { provider: 'polymorphic-local', model: 'deterministic-swarm-v1' }
};

function maskSecret(secret) {
  if (!secret || typeof secret !== 'string') return '';
  const trimmed = secret.trim();
  if (trimmed.length <= 8) return '••••••••';
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-4)}`;
}

function validateAssignment(assignment, fallback) {
  if (!assignment || typeof assignment !== 'object') return { ...fallback };
  const provider = Object.hasOwn(PROVIDER_CATALOG, assignment.provider)
    ? assignment.provider
    : fallback.provider;
  const catalog = PROVIDER_CATALOG[provider];
  const rawCustom = typeof assignment.customModel === 'string' ? assignment.customModel.trim() : '';
  const rawModel = typeof assignment.model === 'string' ? assignment.model.trim() : '';
  const chosenModel = rawCustom || rawModel;

  if (catalog.supportsCustomModel && chosenModel && /^[A-Za-z0-9._:/-]{2,120}$/.test(chosenModel)) {
    return { provider, model: chosenModel };
  }

  const model = catalog.models.includes(chosenModel) ? chosenModel : catalog.models[0];
  return { provider, model };
}

export class AIRouter {
  /**
   * @param {object} [initialConfig]
   */
  constructor(initialConfig = {}) {
    this.config = {
      mode: initialConfig.mode === 'unified' ? 'unified' : 'specialized',
      unified: validateAssignment(
        initialConfig.unified,
        { provider: 'polymorphic-local', model: 'deterministic-swarm-v1' }
      ),
      specialized: {
        SENTINEL: validateAssignment(initialConfig.specialized?.SENTINEL, DEFAULT_ASSIGNMENTS.SENTINEL),
        WEAVER: validateAssignment(initialConfig.specialized?.WEAVER, DEFAULT_ASSIGNMENTS.WEAVER),
        MIRAGE: validateAssignment(initialConfig.specialized?.MIRAGE, DEFAULT_ASSIGNMENTS.MIRAGE),
        CHRONICLER: validateAssignment(initialConfig.specialized?.CHRONICLER, DEFAULT_ASSIGNMENTS.CHRONICLER)
      },
      apiKeys: {
        openrouter: '',
        gemini: '',
        openai: '',
        anthropic: '',
        deepseek: '',
        groq: ''
      },
      ollamaEndpoint: 'http://localhost:11434',
      maxApiCallsPerHour: 50,
      tarpitDelayMs: 1200
    };

    this.budgetState = {
      hourWindowStart: Date.now(),
      apiCallsThisHour: 0,
      totalExternalCalls: 0,
      totalLocalCalls: 0,
      killSwitchTriggers: 0,
      defenseSpendUsd: 0
    };

    if (initialConfig && Object.keys(initialConfig).length > 0) {
      this.updateConfig(initialConfig);
    }
  }

  /**
   * Actualiza de forma segura la configuración de modelos, llaves API (BYOK) y topes de presupuesto.
   * Las llaves vacías o no enviadas conservan las existentes salvo que se pida borrarlas explícitamente.
   * @param {object} patch
   */
  updateConfig(patch = {}) {
    if (patch.mode === 'unified' || patch.mode === 'specialized') {
      this.config.mode = patch.mode;
    }

    if (patch.unified) {
      this.config.unified = validateAssignment(patch.unified, this.config.unified);
    }

    if (patch.specialized && typeof patch.specialized === 'object') {
      for (const id of GUARDIAN_IDS) {
        if (patch.specialized[id]) {
          this.config.specialized[id] = validateAssignment(
            patch.specialized[id],
            this.config.specialized[id]
          );
        }
      }
    }

    if (patch.apiKeys && typeof patch.apiKeys === 'object') {
      for (const provider of Object.keys(this.config.apiKeys)) {
        if (Object.hasOwn(patch.apiKeys, provider) && typeof patch.apiKeys[provider] === 'string') {
          const val = patch.apiKeys[provider].trim();
          // Ignora placeholders enmascarados enviados por el navegador
          if (val && !val.includes('••••')) {
            this.config.apiKeys[provider] = val;
          } else if (val === '__CLEAR__') {
            this.config.apiKeys[provider] = '';
          }
        }
      }
    }

    if (typeof patch.ollamaEndpoint === 'string' && patch.ollamaEndpoint.trim()) {
      const cleanUrl = patch.ollamaEndpoint.trim().replace(/\/+$/, '');
      if (cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://')) {
        this.config.ollamaEndpoint = cleanUrl;
      }
    }

    if (patch.maxApiCallsPerHour !== undefined) {
      const limit = Number(patch.maxApiCallsPerHour);
      if (Number.isFinite(limit) && limit >= 0 && limit <= 10000) {
        this.config.maxApiCallsPerHour = Math.floor(limit);
      }
    }

    if (patch.tarpitDelayMs !== undefined) {
      const delay = Number(patch.tarpitDelayMs);
      if (Number.isFinite(delay) && delay >= 0 && delay <= 10000) {
        this.config.tarpitDelayMs = Math.floor(delay);
      }
    }

    return this.getPublicConfig();
  }

  /**
   * Persiste configuración (y llaves BYOK cifradas con AES-256-GCM) en SQLite.
   */
  saveToStore(store) {
    if (!store) return;
    store.saveSetting('ai_config_public', {
      mode: this.config.mode,
      unified: this.config.unified,
      specialized: this.config.specialized,
      ollamaEndpoint: this.config.ollamaEndpoint,
      maxApiCallsPerHour: this.config.maxApiCallsPerHour,
      tarpitDelayMs: this.config.tarpitDelayMs
    });
    store.saveSetting('ai_keys_vault', store.encryptSecretObject(this.config.apiKeys));
  }

  /**
   * Restaura configuración de IA y llaves cifradas desde SQLite.
   */
  loadFromStore(store) {
    if (!store) return;
    const savedCfg = store.loadSetting('ai_config_public', null);
    const savedVault = store.loadSetting('ai_keys_vault', null);
    const decryptedKeys = savedVault ? store.decryptSecretObject(savedVault) : null;
    if (savedCfg || decryptedKeys) {
      this.updateConfig({
        ...(savedCfg || {}),
        apiKeys: decryptedKeys || undefined
      });
    }
  }

  /**
   * Devuelve el estado de configuración sin exponer llaves secretas en texto plano.
   */
  getPublicConfig() {
    this._refreshHourWindow();
    const apiKeyStatus = {};
    for (const [provider, secret] of Object.entries(this.config.apiKeys)) {
      apiKeyStatus[provider] = {
        configured: Boolean(secret),
        masked: maskSecret(secret)
      };
    }

    return {
      mode: this.config.mode,
      unified: { ...this.config.unified },
      specialized: {
        SENTINEL: { ...this.config.specialized.SENTINEL },
        WEAVER: { ...this.config.specialized.WEAVER },
        MIRAGE: { ...this.config.specialized.MIRAGE },
        CHRONICLER: { ...this.config.specialized.CHRONICLER }
      },
      activePerGuardian: {
        SENTINEL: this.resolveAssignment('SENTINEL'),
        WEAVER: this.resolveAssignment('WEAVER'),
        MIRAGE: this.resolveAssignment('MIRAGE'),
        CHRONICLER: this.resolveAssignment('CHRONICLER')
      },
      apiKeyStatus,
      ollamaEndpoint: this.config.ollamaEndpoint,
      maxApiCallsPerHour: this.config.maxApiCallsPerHour,
      tarpitDelayMs: this.config.tarpitDelayMs,
      budgetState: {
        ...this.budgetState,
        killSwitchActive: this.budgetState.apiCallsThisHour >= this.config.maxApiCallsPerHour
      },
      catalog: PROVIDER_CATALOG
    };
  }

  /**
   * Resuelve qué proveedor y modelo le corresponde a un Guardián específico.
   * @param {string} guardianId
   */
  resolveAssignment(guardianId) {
    if (this.config.mode === 'unified') {
      return { ...this.config.unified };
    }
    return { ...(this.config.specialized[guardianId] || DEFAULT_ASSIGNMENTS.SENTINEL) };
  }

  _refreshHourWindow() {
    const now = Date.now();
    if (now - this.budgetState.hourWindowStart >= 3600_000) {
      this.budgetState.hourWindowStart = now;
      this.budgetState.apiCallsThisHour = 0;
    }
  }

  /**
   * Comprueba si el Escudo Anti-Gasto permite una llamada externa para este proveedor.
   * @param {string} provider
   */
  canUseExternalProvider(provider) {
    this._refreshHourWindow();
    const meta = PROVIDER_CATALOG[provider];
    if (!meta || provider === 'polymorphic-local') return false;

    if (meta.requiresApiKey && !this.config.apiKeys[provider]) {
      return false;
    }

    if (provider !== 'ollama' && this.budgetState.apiCallsThisHour >= this.config.maxApiCallsPerHour) {
      this.budgetState.killSwitchTriggers += 1;
      return false;
    }

    return true;
  }

  /**
   * Ejecuta generación de texto con fallback garantizado al Motor Polimórfico Local ($0.00).
   * Los flujos de alto volumen del laberinto (`forceLocalOnly: true`) nunca consumen APIs externas.
   * @param {object} options
   * @param {string} options.guardianId
   * @param {string} options.prompt
   * @param {Function} options.fallbackBuilder
   * @param {boolean} [options.forceLocalOnly=false]
   * @param {number} [options.timeoutMs=4500]
   */
  async generateText({
    guardianId,
    prompt,
    fallbackBuilder,
    forceLocalOnly = false,
    timeoutMs = 4500
  }) {
    const assignment = this.resolveAssignment(guardianId);

    if (forceLocalOnly || !this.canUseExternalProvider(assignment.provider)) {
      this.budgetState.totalLocalCalls += 1;
      return {
        text: fallbackBuilder(),
        provider: 'polymorphic-local',
        model: 'deterministic-swarm-v1',
        requestedProvider: assignment.provider,
        requestedModel: assignment.model,
        usedFallback: assignment.provider !== 'polymorphic-local',
        costUsd: 0
      };
    }

    try {
      const text = await this._invokeExternalProvider(assignment, prompt, timeoutMs);
      if (assignment.provider !== 'ollama') {
        this.budgetState.apiCallsThisHour += 1;
        this.budgetState.totalExternalCalls += 1;
        const estCost = PROVIDER_CATALOG[assignment.provider]?.costPerCallEstimateUsd || 0;
        this.budgetState.defenseSpendUsd = Number((this.budgetState.defenseSpendUsd + estCost).toFixed(6));
      } else {
        this.budgetState.totalLocalCalls += 1;
      }

      return {
        text,
        provider: assignment.provider,
        model: assignment.model,
        requestedProvider: assignment.provider,
        requestedModel: assignment.model,
        usedFallback: false,
        costUsd: PROVIDER_CATALOG[assignment.provider]?.costPerCallEstimateUsd || 0
      };
    } catch {
      this.budgetState.totalLocalCalls += 1;
      return {
        text: fallbackBuilder(),
        provider: 'polymorphic-local',
        model: 'deterministic-swarm-v1',
        requestedProvider: assignment.provider,
        requestedModel: assignment.model,
        usedFallback: true,
        costUsd: 0
      };
    }
  }

  async _invokeExternalProvider({ provider, model }, prompt, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      if (provider === 'gemini') {
        const key = encodeURIComponent(this.config.apiKeys.gemini);
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${key}`;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.3, maxOutputTokens: 500 }
          }),
          signal: controller.signal
        });
        if (!res.ok) throw new Error(`Gemini HTTP ${res.status}`);
        const data = await res.json();
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) throw new Error('Gemini empty output');
        return text.trim();
      }

      if (provider === 'openrouter' || provider === 'openai' || provider === 'deepseek' || provider === 'groq') {
        const endpoints = {
          openrouter: 'https://openrouter.ai/api/v1/chat/completions',
          openai: 'https://api.openai.com/v1/chat/completions',
          deepseek: 'https://api.deepseek.com/chat/completions',
          groq: 'https://api.groq.com/openai/v1/chat/completions'
        };
        const headers = {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.config.apiKeys[provider]}`
        };
        if (provider === 'openrouter') {
          headers['HTTP-Referer'] = 'https://www.365collaboration.net';
          headers['X-Title'] = 'Guardianes Eternos SOC';
        }
        const res = await fetch(endpoints[provider], {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            messages: [
              { role: 'system', content: 'Eres un agente defensivo de ciberseguridad del enjambre Guardianes Eternos. Sé preciso y conciso.' },
              { role: 'user', content: prompt }
            ],
            temperature: 0.3,
            max_tokens: 500
          }),
          signal: controller.signal
        });
        if (!res.ok) throw new Error(`${provider} HTTP ${res.status}`);
        const data = await res.json();
        const text = data?.choices?.[0]?.message?.content;
        if (!text) throw new Error(`${provider} empty output`);
        return text.trim();
      }

      if (provider === 'anthropic') {
        const res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.config.apiKeys.anthropic,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model,
            max_tokens: 500,
            messages: [{ role: 'user', content: prompt }]
          }),
          signal: controller.signal
        });
        if (!res.ok) throw new Error(`Anthropic HTTP ${res.status}`);
        const data = await res.json();
        const text = data?.content?.[0]?.text;
        if (!text) throw new Error('Anthropic empty output');
        return text.trim();
      }

      if (provider === 'ollama') {
        const res = await fetch(`${this.config.ollamaEndpoint}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, prompt, stream: false }),
          signal: controller.signal
        });
        if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
        const data = await res.json();
        if (!data?.response) throw new Error('Ollama empty output');
        return String(data.response).trim();
      }

      throw new Error(`Unsupported provider: ${provider}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Consulta el catálogo en vivo de OpenRouter (https://openrouter.ai/api/v1/models)
   * manteniendo la lista curada como respaldo si no hay conexión externa.
   */
  async fetchOpenRouterModels(timeoutMs = 5000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const baseModels = [...PROVIDER_CATALOG.openrouter.models];

    try {
      const headers = { Accept: 'application/json' };
      if (this.config.apiKeys.openrouter) {
        headers.Authorization = `Bearer ${this.config.apiKeys.openrouter}`;
      }
      const res = await fetch('https://openrouter.ai/api/v1/models', {
        method: 'GET',
        headers,
        signal: controller.signal
      });
      if (!res.ok) {
        return { live: false, models: baseModels };
      }
      const data = await res.json();
      const ids = Array.isArray(data?.data)
        ? data.data.map((m) => m?.id).filter((id) => typeof id === 'string')
        : [];
      if (ids.length === 0) {
        return { live: false, models: baseModels };
      }
      const freeModels = ids.filter((id) => id.endsWith(':free')).slice(0, 25);
      const topOthers = ids.filter((id) => !id.endsWith(':free')).slice(0, 35);
      const merged = Array.from(new Set([...baseModels, ...freeModels, ...topOthers]));
      PROVIDER_CATALOG.openrouter.models = merged;
      return { live: true, totalAvailable: ids.length, models: merged };
    } catch {
      return { live: false, models: baseModels };
    } finally {
      clearTimeout(timer);
    }
  }
}

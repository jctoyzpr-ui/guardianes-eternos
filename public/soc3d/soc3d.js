/**
 * @fileoverview Guardianes Eternos v5.0 — SOC Holográfico 3D (Three.js + OrbitControls).
 * Renderiza en tiempo real:
 *   - Núcleo Central Fresnel (IcosahedronGeometry) pulsando con tráfico legítimo.
 *   - 4 Anillos Orbitales de Guardianes (Centinela, Tejedor, Ilusionista, Cronista).
 *   - Satélite Comandante Hermes con haz de mando animado.
 *   - Enjambre de partículas legítimas (InstancedMesh verde) y trayectorias hostiles desviadas
 *     hacia el Vórtice Polar Tarpit + Laberinto 3D (CatmullRomCurve3).
 *   - Raycasting al clic sobre nodos atacantes para inspeccionar su expediente forense.
 * Incluye fallback automático 3D en Canvas2D si WebGL/CDN no están disponibles,
 * pausa en document.hidden y respeto por prefers-reduced-motion.
 */

const THREE_CDN = 'https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.js';
const ORBIT_CDN = 'https://cdn.jsdelivr.net/npm/three@0.170.0/examples/jsm/controls/OrbitControls.js';

const GUARDIAN_RING_SPECS = [
  { id: 'SENTINEL', label: 'Centinela WAF', radius: 2.55, color: 0x10b981, hex: '#10b981', tiltX: 0.42, tiltZ: 0.15, speed: 0.55 },
  { id: 'WEAVER', label: 'Tejedor Tarpit', radius: 3.35, color: 0x22d3ee, hex: '#22d3ee', tiltX: -0.52, tiltZ: 0.35, speed: -0.42 },
  { id: 'MIRAGE', label: 'Ilusionista IDPI', radius: 4.15, color: 0xa78bfa, hex: '#a78bfa', tiltX: 0.68, tiltZ: -0.28, speed: 0.34 },
  { id: 'CHRONICLER', label: 'Cronista Forense', radius: 4.9, color: 0xf59e0b, hex: '#f59e0b', tiltX: -0.3, tiltZ: -0.48, speed: -0.26 }
];

function hashAngle(str) {
  let h = 2166136261;
  const s = String(str || 'node');
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 3600) / 3600 * Math.PI * 2;
}

export class HolographicSoc3D {
  constructor(container, { onThreatSelect = null, onEngineReady = null } = {}) {
    this.container = container;
    this.onThreatSelect = onThreatSelect;
    this.onEngineReady = onEngineReady;
    this.reducedMotion = Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches);
    this.paused = false;
    this.destroyed = false;
    this.engineMode = 'initializing';
    this.threats = [];
    this.metrics = {
      totalLegitRequests: 0,
      totalBlockedOrTrappedHits: 0,
      quarantinedCount: 0,
      tarpitSocketsInUse: 0,
      totalDecoyNodesGenerated: 0
    };
    this.pulses = [];
    this._rafId = null;
    this._onVisibility = () => {
      this.paused = document.hidden;
    };
    document.addEventListener('visibilitychange', this._onVisibility);
  }

  async init() {
    if (!this.container) return;
    try {
      const [THREE, orbitMod] = await Promise.all([
        import(/* @vite-ignore */ THREE_CDN),
        import(/* @vite-ignore */ ORBIT_CDN)
      ]);
      if (this.destroyed) return;
      this._initThreeEngine(THREE, orbitMod.OrbitControls);
      this.engineMode = 'webgl-threejs';
    } catch {
      if (this.destroyed) return;
      this._initFallbackCanvas3D();
      this.engineMode = 'canvas-3d-fallback';
    }
    if (typeof this.onEngineReady === 'function') {
      this.onEngineReady(this.engineMode);
    }
  }

  updateSnapshot(snapshot) {
    if (!snapshot) return;
    this.threats = Array.isArray(snapshot.threats) ? snapshot.threats.slice(0, 28) : [];
    if (snapshot.metrics) {
      this.metrics = { ...this.metrics, ...snapshot.metrics };
    }
    if (this._rebuildThreatObjects) {
      this._rebuildThreatObjects();
    }
  }

  triggerPulse(kind = 'threat', payload = {}) {
    this.pulses.push({
      kind,
      payload,
      createdAt: performance.now(),
      durationMs: 1800
    });
    if (this.pulses.length > 24) this.pulses.shift();
  }

  setPaused(flag) {
    this.paused = Boolean(flag);
  }

  _initThreeEngine(THREE, OrbitControls) {
    this.THREE = THREE;
    const width = Math.max(320, this.container.clientWidth || 900);
    const height = Math.max(340, this.container.clientHeight || 440);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x040812, 0.032);

    const camera = new THREE.PerspectiveCamera(46, width / height, 0.1, 120);
    camera.position.set(0, 4.4, 11.4);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.15;

    this.container.replaceChildren(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.minDistance = 5.5;
    controls.maxDistance = 22;
    controls.autoRotate = !this.reducedMotion;
    controls.autoRotateSpeed = 0.42;

    // Iluminación
    scene.add(new THREE.AmbientLight(0x3b82f6, 0.7));
    const coreLight = new THREE.PointLight(0x22d3ee, 2.4, 24);
    coreLight.position.set(0, 1.5, 0);
    scene.add(coreLight);
    const vortexLight = new THREE.PointLight(0xef4444, 2.2, 18);
    vortexLight.position.set(0, -4.2, 0);
    scene.add(vortexLight);

    // Rejilla polar holográfica base
    const grid = new THREE.PolarGridHelper(8.5, 16, 7, 64, 0x1e3a5f, 0x132642);
    grid.position.y = -3.8;
    grid.material.transparent = true;
    grid.material.opacity = 0.45;
    scene.add(grid);

    // 1. Núcleo Central Fresnel (IcosahedronGeometry)
    const coreGeo = new THREE.IcosahedronGeometry(1.45, 2);
    const coreMat = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uColorInner: { value: new THREE.Color(0x064e3b) },
        uColorRim: { value: new THREE.Color(0x22d3ee) },
        uAlertMix: { value: 0 }
      },
      vertexShader: `
        varying vec3 vNormal;
        varying vec3 vViewPos;
        uniform float uTime;
        void main() {
          vec3 displaced = position * (1.0 + 0.025 * sin(uTime * 2.4 + position.y * 3.0));
          vec4 mvPos = modelViewMatrix * vec4(displaced, 1.0);
          vViewPos = -mvPos.xyz;
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * mvPos;
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        varying vec3 vViewPos;
        uniform vec3 uColorInner;
        uniform vec3 uColorRim;
        uniform float uAlertMix;
        void main() {
          vec3 viewDir = normalize(vViewPos);
          float fresnel = pow(1.0 - max(dot(viewDir, normalize(vNormal)), 0.0), 2.4);
          vec3 rimColor = mix(uColorRim, vec3(0.95, 0.28, 0.32), uAlertMix);
          vec3 col = mix(uColorInner, rimColor, fresnel);
          gl_FragColor = vec4(col, 0.45 + fresnel * 0.55);
        }
      `,
      transparent: true
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreMesh);

    const wireCore = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.5, 1),
      new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.38 })
    );
    scene.add(wireCore);

    // 2. Cuatro Anillos Orbitales de Guardianes + Nodos Satélite
    const guardianRig = [];
    for (const spec of GUARDIAN_RING_SPECS) {
      const group = new THREE.Group();
      group.rotation.x = spec.tiltX;
      group.rotation.z = spec.tiltZ;

      const torus = new THREE.Mesh(
        new THREE.TorusGeometry(spec.radius, 0.028, 12, 96),
        new THREE.MeshBasicMaterial({ color: spec.color, transparent: true, opacity: 0.55 })
      );
      torus.rotation.x = Math.PI / 2;
      group.add(torus);

      const sat = new THREE.Mesh(
        new THREE.OctahedronGeometry(0.22, 0),
        new THREE.MeshStandardMaterial({
          color: spec.color,
          emissive: spec.color,
          emissiveIntensity: 0.85,
          roughness: 0.25,
          metalness: 0.6
        })
      );
      sat.position.set(spec.radius, 0, 0);
      group.add(sat);

      scene.add(group);
      guardianRig.push({ group, sat, spec, angle: Math.random() * Math.PI * 2 });
    }

    // 3. Satélite Comandante Hermes (polo norte + haz táctico)
    const hermesMesh = new THREE.Mesh(
      new THREE.OctahedronGeometry(0.42, 0),
      new THREE.MeshStandardMaterial({
        color: 0xc084fc,
        emissive: 0x7c3aed,
        emissiveIntensity: 1.1,
        metalness: 0.7,
        roughness: 0.2
      })
    );
    hermesMesh.position.set(0, 3.65, 0);
    scene.add(hermesMesh);

    const hermesRing = new THREE.Mesh(
      new THREE.TorusGeometry(0.72, 0.02, 8, 48),
      new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.7 })
    );
    hermesRing.position.copy(hermesMesh.position);
    hermesRing.rotation.x = Math.PI / 2;
    scene.add(hermesRing);

    const beamGeo = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(0, 3.65, 0),
      new THREE.Vector3(0, 1.5, 0)
    ]);
    const beamMat = new THREE.LineBasicMaterial({ color: 0xa78bfa, transparent: true, opacity: 0.45 });
    const hermesBeam = new THREE.Line(beamGeo, beamMat);
    scene.add(hermesBeam);

    // 4. Partículas de Tráfico Legítimo (InstancedMesh verde)
    const PARTICLE_COUNT = 54;
    const pGeo = new THREE.SphereGeometry(0.06, 6, 6);
    const pMat = new THREE.MeshBasicMaterial({ color: 0x10b981 });
    const legitMesh = new THREE.InstancedMesh(pGeo, pMat, PARTICLE_COUNT);
    const legitSeeds = Array.from({ length: PARTICLE_COUNT }, (_, idx) => ({
      theta: (idx / PARTICLE_COUNT) * Math.PI * 2,
      phi: ((idx * 37) % 180 - 90) * (Math.PI / 180) * 0.55,
      progress: Math.random(),
      speed: 0.14 + Math.random() * 0.14
    }));
    scene.add(legitMesh);

    // 5. Vórtice Polar Tarpit + Grupo Dinámico de Amenazas Desviadas
    const vortexRing = new THREE.Mesh(
      new THREE.TorusGeometry(2.1, 0.05, 10, 64),
      new THREE.MeshBasicMaterial({ color: 0xef4444, transparent: true, opacity: 0.45 })
    );
    vortexRing.rotation.x = Math.PI / 2;
    vortexRing.position.y = -3.4;
    scene.add(vortexRing);

    const threatGroup = new THREE.Group();
    scene.add(threatGroup);
    const clickableThreatMeshes = [];
    const threatTrajectories = [];

    const dummy = new THREE.Object3D();

    this._rebuildThreatObjects = () => {
      while (threatGroup.children.length > 0) {
        const child = threatGroup.children.pop();
        child.geometry?.dispose?.();
        child.material?.dispose?.();
      }
      clickableThreatMeshes.length = 0;
      threatTrajectories.length = 0;

      const list = this.threats.slice(0, 24);
      list.forEach((t, idx) => {
        const angle = hashAngle(t.actorKey || t.ip || idx);
        const outerR = 7.4;
        const shieldR = 2.65;
        const vortexR = 1.2 + (idx % 5) * 0.34;
        const vortexY = -3.1 - (idx % 4) * 0.22;

        const p0 = new THREE.Vector3(Math.cos(angle) * outerR, 1.8 - (idx % 3) * 0.7, Math.sin(angle) * outerR);
        const p1 = new THREE.Vector3(Math.cos(angle + 0.12) * shieldR, 0.5, Math.sin(angle + 0.12) * shieldR);
        const p2 = new THREE.Vector3(
          Math.cos(angle + 1.05) * (vortexR + 1.4),
          -1.6,
          Math.sin(angle + 1.05) * (vortexR + 1.4)
        );
        const p3 = new THREE.Vector3(
          Math.cos(angle + 2.15) * vortexR,
          vortexY,
          Math.sin(angle + 2.15) * vortexR
        );

        const curve = new THREE.CatmullRomCurve3([p0, p1, p2, p3]);
        const pts = curve.getPoints(36);
        const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
        const lineMat = new THREE.LineBasicMaterial({
          color: t.quarantined ? 0xef4444 : 0xf59e0b,
          transparent: true,
          opacity: t.quarantined ? 0.75 : 0.52
        });
        threatGroup.add(new THREE.Line(lineGeo, lineMat));

        // Nodo atacante atrapado en el Vórtice Polar (clickeable)
        const nodeColor = t.quarantined ? 0xef4444 : 0xf59e0b;
        const nodeMesh = new THREE.Mesh(
          new THREE.OctahedronGeometry(t.quarantined ? 0.28 : 0.22, 0),
          new THREE.MeshStandardMaterial({
            color: nodeColor,
            emissive: nodeColor,
            emissiveIntensity: 0.9,
            roughness: 0.3
          })
        );
        nodeMesh.position.copy(p3);
        nodeMesh.userData = { threat: t };
        threatGroup.add(nodeMesh);
        clickableThreatMeshes.push(nodeMesh);

        // Paquete hostil animado recorriendo la curva de desvío
        const packet = new THREE.Mesh(
          new THREE.SphereGeometry(0.09, 8, 8),
          new THREE.MeshBasicMaterial({ color: 0xfca5a5 })
        );
        threatGroup.add(packet);
        threatTrajectories.push({ curve, packet, nodeMesh, offset: (idx * 0.17) % 1 });
      });
    };

    this._rebuildThreatObjects();

    // Raycaster para seleccionar un atacante en 3D
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const onPointerDown = (ev) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(clickableThreatMeshes, false);
      if (hits.length > 0 && typeof this.onThreatSelect === 'function') {
        this.onThreatSelect(hits[0].object.userData.threat);
      }
    };
    renderer.domElement.addEventListener('pointerdown', onPointerDown);

    // ResizeObserver
    const ro = new ResizeObserver(() => {
      if (this.destroyed) return;
      const w = Math.max(320, this.container.clientWidth || 900);
      const h = Math.max(340, this.container.clientHeight || 440);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
    ro.observe(this.container);
    this._cleanupThree = () => {
      ro.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      controls.dispose();
      renderer.dispose();
    };

    const clock = new THREE.Clock();
    const animate = () => {
      if (this.destroyed) return;
      this._rafId = requestAnimationFrame(animate);
      if (this.paused) return;

      const dt = Math.min(clock.getDelta(), 0.05);
      const elapsed = clock.elapsedTime;
      const speedScale = this.reducedMotion ? 0.15 : 1;

      coreMat.uniforms.uTime.value = elapsed;
      const alertRatio = Math.min(1, (this.metrics.quarantinedCount || 0) / 8);
      coreMat.uniforms.uAlertMix.value += (alertRatio - coreMat.uniforms.uAlertMix.value) * 0.06;

      coreMesh.rotation.y += dt * 0.25 * speedScale;
      wireCore.rotation.y -= dt * 0.18 * speedScale;
      hermesMesh.rotation.y += dt * 0.9 * speedScale;
      hermesMesh.position.y = 3.65 + Math.sin(elapsed * 2.2) * 0.12;
      hermesRing.position.y = hermesMesh.position.y;
      hermesRing.rotation.z += dt * 0.8 * speedScale;

      // Anillos y satélites guardianes
      for (const item of guardianRig) {
        item.angle += dt * item.spec.speed * speedScale;
        item.sat.position.set(
          Math.cos(item.angle) * item.spec.radius,
          0,
          Math.sin(item.angle) * item.spec.radius
        );
        item.sat.rotation.y += dt * 1.4 * speedScale;
      }

      // Flujo verde legítimo hacia el núcleo
      for (let i = 0; i < PARTICLE_COUNT; i += 1) {
        const s = legitSeeds[i];
        s.progress = (s.progress + dt * s.speed * speedScale) % 1;
        const r = 7.2 - s.progress * 5.6;
        const x = Math.cos(s.theta + elapsed * 0.15) * Math.cos(s.phi) * r;
        const y = Math.sin(s.phi) * r + 0.4;
        const z = Math.sin(s.theta + elapsed * 0.15) * Math.cos(s.phi) * r;
        dummy.position.set(x, y, z);
        const sc = 0.6 + (1 - s.progress) * 0.6;
        dummy.scale.setScalar(sc);
        dummy.updateMatrix();
        legitMesh.setMatrixAt(i, dummy.matrix);
      }
      legitMesh.instanceMatrix.needsUpdate = true;

      // Trayectorias hostiles hacia el vórtice
      vortexRing.rotation.z -= dt * 0.7 * speedScale;
      for (const tr of threatTrajectories) {
        const u = (elapsed * 0.28 * speedScale + tr.offset) % 1;
        const pos = tr.curve.getPointAt(u);
        tr.packet.position.copy(pos);
        tr.nodeMesh.rotation.y += dt * 1.6 * speedScale;
      }

      controls.update();
      renderer.render(scene, camera);
    };

    animate();
  }

  /**
   * Fallback 3D en perspectiva sobre Canvas2D (sin CDN/WebGL) manteniendo el mismo diseño holográfico.
   */
  _initFallbackCanvas3D() {
    const canvas = document.createElement('canvas');
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.display = 'block';
    this.container.replaceChildren(canvas);
    const ctx = canvas.getContext('2d');
    let rotY = 0;
    const hitTargets = [];

    const resize = () => {
      const w = Math.max(320, this.container.clientWidth || 900);
      const h = Math.max(340, this.container.clientHeight || 440);
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const ro = new ResizeObserver(resize);
    ro.observe(this.container);

    const onClick = (ev) => {
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      for (const ht of hitTargets) {
        if (Math.hypot(mx - ht.x, my - ht.y) <= 16) {
          if (typeof this.onThreatSelect === 'function') this.onThreatSelect(ht.threat);
          break;
        }
      }
    };
    canvas.addEventListener('click', onClick);
    this._cleanupFallback = () => {
      ro.disconnect();
      canvas.removeEventListener('click', onClick);
    };

    const project = (x, y, z, w, h) => {
      const cy = Math.cos(rotY);
      const sy = Math.sin(rotY);
      const rx = x * cy - z * sy;
      const rz = x * sy + z * cy;
      const fov = 420;
      const dist = 10.5;
      const scale = fov / Math.max(1.5, dist - rz);
      return { x: w / 2 + rx * scale, y: h / 2 - y * scale, scale, z: rz };
    };

    const drawFrame = (ts) => {
      if (this.destroyed) return;
      this._rafId = requestAnimationFrame(drawFrame);
      if (this.paused) return;

      const w = this.container.clientWidth || 900;
      const h = this.container.clientHeight || 440;
      const t = ts * 0.001;
      rotY += this.reducedMotion ? 0.001 : 0.0055;

      ctx.clearRect(0, 0, w, h);
      const bgGrad = ctx.createRadialGradient(w / 2, h / 2, 10, w / 2, h / 2, w * 0.55);
      bgGrad.addColorStop(0, '#0a1930');
      bgGrad.addColorStop(1, '#040812');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, w, h);

      // Núcleo central holográfico
      const coreP = project(0, 0.2, 0, w, h);
      const pulse = 38 + Math.sin(t * 2.5) * 3;
      const coreGrad = ctx.createRadialGradient(coreP.x, coreP.y, 4, coreP.x, coreP.y, pulse * 1.4);
      coreGrad.addColorStop(0, 'rgba(34,211,238,0.85)');
      coreGrad.addColorStop(0.6, 'rgba(16,185,129,0.35)');
      coreGrad.addColorStop(1, 'rgba(16,185,129,0)');
      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(coreP.x, coreP.y, pulse * 1.4, 0, Math.PI * 2);
      ctx.fill();

      // 4 anillos orbitales guardianes
      for (const spec of GUARDIAN_RING_SPECS) {
        ctx.strokeStyle = spec.hex;
        ctx.globalAlpha = 0.52;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        for (let i = 0; i <= 48; i += 1) {
          const a = (i / 48) * Math.PI * 2;
          const px = Math.cos(a) * spec.radius;
          const py = Math.sin(a) * spec.radius * Math.sin(spec.tiltX);
          const pz = Math.sin(a) * spec.radius * Math.cos(spec.tiltX);
          const p = project(px, py + 0.2, pz, w, h);
          if (i === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        }
        ctx.stroke();

        const satA = t * spec.speed;
        const sp = project(
          Math.cos(satA) * spec.radius,
          Math.sin(satA) * spec.radius * Math.sin(spec.tiltX) + 0.2,
          Math.sin(satA) * spec.radius * Math.cos(spec.tiltX),
          w,
          h
        );
        ctx.globalAlpha = 1;
        ctx.fillStyle = spec.hex;
        ctx.beginPath();
        ctx.arc(sp.x, sp.y, 5, 0, Math.PI * 2);
        ctx.fill();
      }

      // Satélite Hermes
      const hp = project(0, 3.1 + Math.sin(t * 2) * 0.15, 0, w, h);
      ctx.strokeStyle = 'rgba(167,139,250,0.45)';
      ctx.beginPath();
      ctx.moveTo(hp.x, hp.y);
      ctx.lineTo(coreP.x, coreP.y);
      ctx.stroke();
      ctx.fillStyle = '#c084fc';
      ctx.beginPath();
      ctx.arc(hp.x, hp.y, 8, 0, Math.PI * 2);
      ctx.fill();

      // Amenazas en el Vórtice Polar
      hitTargets.length = 0;
      const list = this.threats.slice(0, 20);
      list.forEach((threat, idx) => {
        const a = hashAngle(threat.actorKey || idx) + t * 0.35;
        const pOut = project(Math.cos(a) * 5.6, 1.2, Math.sin(a) * 5.6, w, h);
        const pVor = project(Math.cos(a + 1.4) * 1.9, -2.5, Math.sin(a + 1.4) * 1.9, w, h);

        ctx.strokeStyle = threat.quarantined ? 'rgba(239,68,68,0.65)' : 'rgba(245,158,11,0.55)';
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(pOut.x, pOut.y);
        ctx.quadraticCurveTo(coreP.x, coreP.y + 30, pVor.x, pVor.y);
        ctx.stroke();

        ctx.fillStyle = threat.quarantined ? '#ef4444' : '#f59e0b';
        ctx.beginPath();
        ctx.arc(pVor.x, pVor.y, 6.5, 0, Math.PI * 2);
        ctx.fill();
        hitTargets.push({ x: pVor.x, y: pVor.y, threat });
      });

      ctx.globalAlpha = 1;
    };

    this._rafId = requestAnimationFrame(drawFrame);
  }

  destroy() {
    this.destroyed = true;
    document.removeEventListener('visibilitychange', this._onVisibility);
    if (this._rafId) cancelAnimationFrame(this._rafId);
    this._cleanupThree?.();
    this._cleanupFallback?.();
  }
}

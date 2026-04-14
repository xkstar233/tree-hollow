// static/js/galaxy.js
class Galaxy {
    constructor() {
        const canvas = document.getElementById('galaxy-canvas');
        if (!canvas) return;

        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.renderer = new THREE.WebGLRenderer({
            alpha: true,
            antialias: true,
            canvas: document.getElementById('galaxy-canvas')
        });
        this.asteroids = [];
        this.mouseX = 0;
        this.mouseY = 0;
        this.selectedAsteroid = null;
        this.clock = new THREE.Clock();

        this.init();
        this.animate();
    }

    init() {
        // 设置渲染器
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.setClearColor(0x000000, 0);
        this.renderer.shadowMap.enabled = true;

        // 相机位置
        this.camera.position.set(0, 20, 50);

        // 添加星空背景
        this.createStars();

        // 添加星系中心恒星
        this.createCentralStar();

        // 添加小行星带
        this.createAsteroidBelt();

        // 添加光源
        this.createLights();

        // 鼠标交互事件
        this.setupInteractions();
    }

    createStars() {
        // 创建更真实的星空背景
        const geometry = new THREE.BufferGeometry();
        const vertices = [];
        const sizes = [];
        const colors = [];

        for (let i = 0; i < 10000; i++) {
            // 使用球坐标分布星星
            const radius = 500 + Math.random() * 1000;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            const x = radius * Math.sin(phi) * Math.cos(theta);
            const y = radius * Math.sin(phi) * Math.sin(theta);
            const z = radius * Math.cos(phi);

            vertices.push(x, y, z);

            // 随机大小和颜色
            sizes.push(0.5 + Math.random() * 2);

            // 随机恒星颜色（偏蓝白）
            const colorIntensity = 0.7 + Math.random() * 0.3;
            colors.push(colorIntensity, colorIntensity, 0.9 + Math.random() * 0.1);
        }

        geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
        geometry.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 1,
            sizeAttenuation: true,
            vertexColors: true,
            transparent: true,
            opacity: 0.9,
            blending: THREE.AdditiveBlending
        });

        this.stars = new THREE.Points(geometry, material);
        this.scene.add(this.stars);
    }

    createCentralStar() {
        // 创建星系中心恒星
        const geometry = new THREE.SphereGeometry(8, 64, 64);

        // 使用自定义着色器创建发光效果
        const starMaterial = new THREE.ShaderMaterial({
            uniforms: {
                time: { value: 0 },
                glowColor: { value: new THREE.Color(0xffee88) },
                viewVector: { value: new THREE.Vector3(0, 0, 1) }
            },
            vertexShader: `
                varying vec3 vNormal;
                varying vec3 vPosition;
                void main() {
                    vNormal = normalize(normalMatrix * normal);
                    vPosition = position;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `,
            fragmentShader: `
                uniform vec3 glowColor;
                uniform float time;
                varying vec3 vNormal;
                varying vec3 vPosition;

                void main() {
                    float intensity = pow(0.7 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.0);
                    float pulse = sin(time * 2.0) * 0.1 + 0.9;

                    // 表面纹理
                    vec2 uv = normalize(vPosition).xy * 0.5 + 0.5;
                    float noise = fract(sin(dot(uv, vec2(12.9898, 78.233))) * 43758.5453);

                    // 核心颜色
                    vec3 coreColor = mix(glowColor, vec3(1.0, 0.9, 0.7), noise * 0.3);

                    // 发光效果
                    vec3 glow = glowColor * intensity * pulse * 0.5;

                    gl_FragColor = vec4(coreColor + glow, 1.0);
                }
            `,
            side: THREE.FrontSide,
            blending: THREE.AdditiveBlending
        });

        this.centralStar = new THREE.Mesh(geometry, starMaterial);
        this.centralStar.castShadow = true;
        this.scene.add(this.centralStar);

        // 添加恒星光晕
        const glowGeometry = new THREE.SphereGeometry(10, 32, 32);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: 0xffee88,
            transparent: true,
            opacity: 0.3,
            blending: THREE.AdditiveBlending
        });
        this.starGlow = new THREE.Mesh(glowGeometry, glowMaterial);
        this.scene.add(this.starGlow);
    }

    createAsteroidBelt() {
        // 从DOM获取帖子数据
        const postElements = document.querySelectorAll('.post-data');
        const posts = Array.from(postElements).map(el => ({
            id: el.dataset.id,
            content: el.dataset.content,
            sentiment: el.dataset.sentiment,
            date: el.dataset.date,
            commentCount: el.dataset.comments
        }));

        // 不同情感的颜色和纹理
        const materials = {
            positive: this.createPlanetMaterial(0x88ff88, 'positive'),
            neutral: this.createPlanetMaterial(0xffff88, 'neutral'),
            negative: this.createPlanetMaterial(0xff8888, 'negative')
        };

        // 创建小行星带
        const beltRadius = 20;
        const beltWidth = 30;

        posts.forEach((post, index) => {
            // 随机行星大小
            const size = 0.5 + Math.random() * 1.5;
            const geometry = new THREE.SphereGeometry(size, 32, 32);

            // 根据情感选择材质
            const material = materials[post.sentiment] || materials.neutral;

            const planet = new THREE.Mesh(geometry, material);
            planet.castShadow = true;
            planet.receiveShadow = true;

            // 在环形带中随机分布
            const angle = Math.random() * Math.PI * 2;
            const distance = beltRadius + Math.random() * beltWidth;
            const height = (Math.random() - 0.5) * 10;

            planet.position.x = Math.cos(angle) * distance;
            planet.position.y = height;
            planet.position.z = Math.sin(angle) * distance;

            // 随机旋转和轨道速度
            planet.userData = {
                postId: post.id,
                content: post.content,
                date: post.date,
                commentCount: post.commentCount,
                rotationSpeed: {
                    x: Math.random() * 0.01,
                    y: Math.random() * 0.02,
                    z: Math.random() * 0.01
                },
                orbitSpeed: Math.random() * 0.002 + 0.001,
                orbitRadius: distance,
                orbitHeight: height,
                orbitAngle: angle,
                originalPosition: planet.position.clone()
            };

            // 热门帖子（评论多）添加光环
            if (post.commentCount > 5) {
                this.addPlanetRing(planet, size);
            }

            this.scene.add(planet);
            this.asteroids.push(planet);
        });
    }

    createPlanetMaterial(baseColor, type) {
        // 创建更真实的行星材质
        const textureLoader = new THREE.TextureLoader();

        // 基础颜色
        const color = new THREE.Color(baseColor);

        // 根据类型添加不同纹理特征
        let bumpScale = 0.05;
        let specular = new THREE.Color(0x111111);

        if (type === 'positive') {
            // 绿色星球 - 可能有植被
            color.setHSL(0.3, 0.7, 0.5);
            bumpScale = 0.1;
        } else if (type === 'negative') {
            // 红色星球 - 可能有火山
            color.setHSL(0.02, 0.8, 0.5);
            bumpScale = 0.2;
            specular = new THREE.Color(0x333333);
        } else {
            // 中性 - 沙漠或岩石星球
            color.setHSL(0.1, 0.5, 0.6);
            bumpScale = 0.15;
        }

        // 使用噪声模拟表面纹理
        const noiseTexture = this.generateNoiseTexture(256, 256);

        return new THREE.MeshPhongMaterial({
            color: color,
            specular: specular,
            shininess: 10,
            bumpMap: noiseTexture,
            bumpScale: bumpScale,
            map: noiseTexture,
            reflectivity: 0.1
        });
    }

    generateNoiseTexture(width, height) {
        // 生成噪声纹理用于行星表面
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;

        const context = canvas.getContext('2d');
        const imageData = context.createImageData(width, height);
        const data = imageData.data;

        for (let i = 0; i < data.length; i += 4) {
            const value = Math.random() * 255;
            data[i] = value;
            data[i + 1] = value;
            data[i + 2] = value;
            data[i + 3] = 255;
        }

        context.putImageData(imageData, 0, 0);

        const texture = new THREE.CanvasTexture(canvas);
        texture.wrapS = THREE.RepeatWrapping;
        texture.wrapT = THREE.RepeatWrapping;
        texture.repeat.set(4, 2);

        return texture;
    }

    addPlanetRing(planet, planetSize) {
        // 添加行星环
        const ringInnerRadius = planetSize * 1.5;
        const ringOuterRadius = planetSize * 2.5;
        const ringGeometry = new THREE.RingGeometry(ringInnerRadius, ringOuterRadius, 64);

        // 旋转环使其与行星赤道对齐
        ringGeometry.rotateX(Math.PI / 2);

        // 创建带有纹理的环材质
        const ringTexture = this.generateRingTexture(256, 64);
        const ringMaterial = new THREE.MeshPhongMaterial({
            map: ringTexture,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.8,
            specular: new THREE.Color(0x333333),
            shininess: 30
        });

        const ring = new THREE.Mesh(ringGeometry, ringMaterial);
        ring.receiveShadow = true;
        planet.add(ring);
    }

    generateRingTexture(width, height) {
        // 生成行星环纹理
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;

        const context = canvas.getContext('2d');
        const gradient = context.createLinearGradient(0, 0, width, 0);

        // 创建环的条纹效果
        gradient.addColorStop(0, 'rgba(150, 150, 150, 0)');
        gradient.addColorStop(0.1, 'rgba(200, 200, 200, 0.8)');
        gradient.addColorStop(0.3, 'rgba(180, 180, 180, 0.6)');
        gradient.addColorStop(0.5, 'rgba(220, 220, 220, 0.9)');
        gradient.addColorStop(0.7, 'rgba(180, 180, 180, 0.6)');
        gradient.addColorStop(0.9, 'rgba(200, 200, 200, 0.8)');
        gradient.addColorStop(1, 'rgba(150, 150, 150, 0)');

        context.fillStyle = gradient;
        context.fillRect(0, 0, width, height);

        // 添加一些噪声
        const imageData = context.getImageData(0, 0, width, height);
        const data = imageData.data;

        for (let i = 0; i < data.length; i += 4) {
            if (Math.random() > 0.9) {
                data[i] = 255;
                data[i + 1] = 255;
                data[i + 2] = 255;
            }
        }

        context.putImageData(imageData, 0, 0);

        return new THREE.CanvasTexture(canvas);
    }

    createLights() {
        // 环境光
        const ambientLight = new THREE.AmbientLight(0x404040);
        this.scene.add(ambientLight);

        // 中心恒星光源
        const starLight = new THREE.PointLight(0xffee88, 1, 100);
        starLight.position.set(0, 0, 0);
        starLight.castShadow = true;
        starLight.shadow.mapSize.width = 2048;
        starLight.shadow.mapSize.height = 2048;
        this.scene.add(starLight);

        // 平行光模拟远处恒星
        const directionalLight = new THREE.DirectionalLight(0xffffff, 0.5);
        directionalLight.position.set(1, 1, 1);
        this.scene.add(directionalLight);
    }

    setupInteractions() {
        // 鼠标移动事件
        document.addEventListener('mousemove', (event) => {
            this.mouseX = (event.clientX - window.innerWidth / 2) * 0.005;
            this.mouseY = (event.clientY - window.innerHeight / 2) * 0.005;
        });

        // 点击事件
        document.addEventListener('click', (event) => {
            const mouse = new THREE.Vector2(
                (event.clientX / window.innerWidth) * 2 - 1,
                -(event.clientY / window.innerHeight) * 2 + 1
            );

            const raycaster = new THREE.Raycaster();
            raycaster.setFromCamera(mouse, this.camera);

            const intersects = raycaster.intersectObjects(this.asteroids);
            if (intersects.length > 0) {
                const planet = intersects[0].object;
                const postId = planet.userData.postId;
                window.location.href = `/post/${postId}`;
            }
        });

        // 窗口大小调整
        window.addEventListener('resize', () => {
            this.camera.aspect = window.innerWidth / window.innerHeight;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(window.innerWidth, window.innerHeight);
        });

        // 缩放控制
        document.getElementById('zoom-out-btn').addEventListener('click', () => {
            this.camera.position.z += 5;
        });

        document.getElementById('zoom-in-btn').addEventListener('click', () => {
            if (this.camera.position.z > 20) {
                this.camera.position.z -= 5;
            }
        });
    }

    animate() {
        requestAnimationFrame(() => this.animate());

        const delta = this.clock.getDelta();
        const time = this.clock.getElapsedTime();

        // 更新恒星材质时间
        if (this.centralStar.material.uniforms) {
            this.centralStar.material.uniforms.time.value = time;
        }

        // 恒星脉动效果
        this.starGlow.scale.setScalar(1 + Math.sin(time * 2) * 0.05);

        // 行星动画
        this.asteroids.forEach(planet => {
            // 自转
            planet.rotation.x += planet.userData.rotationSpeed.x;
            planet.rotation.y += planet.userData.rotationSpeed.y;
            planet.rotation.z += planet.userData.rotationSpeed.z;

            // 公转
            planet.userData.orbitAngle += planet.userData.orbitSpeed;
            planet.position.x = Math.cos(planet.userData.orbitAngle) * planet.userData.orbitRadius;
            planet.position.z = Math.sin(planet.userData.orbitAngle) * planet.userData.orbitRadius;

            // 轻微上下浮动
            planet.position.y = planet.userData.orbitHeight + Math.sin(time + planet.userData.orbitAngle) * 0.5;
        });

        // 星空缓慢旋转
        if (this.stars) {
            this.stars.rotation.y += 0.0001;
        }

        // 相机跟随鼠标
        this.camera.position.x += (this.mouseX * 10 - this.camera.position.x) * 0.05;
        this.camera.position.y += (-this.mouseY * 10 - this.camera.position.y) * 0.05;
        this.camera.lookAt(this.scene.position);

        this.renderer.render(this.scene, this.camera);
    }
}
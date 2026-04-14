const GLTFLoader = THREE.GLTFLoader;

class LittlePrinceGalaxy {
    constructor() {
        this.canvas = document.getElementById('galaxy-canvas');
        if (!this.canvas) return;  // 没有画布就不干任何事

        // 更强制性的方式确保画布不拦截事件
        this.canvas.style.pointerEvents = 'none';
        this.canvas.style.zIndex = '-1';  // 确保画布在底层
        this.canvas.style.position = 'fixed';  // 防止布局问题

        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.renderer = new THREE.WebGLRenderer({
            alpha: true,
            antialias: true,
            canvas: document.getElementById('galaxy-canvas')
        });
        this.planets = [];
        this.mouseX = 0;
        this.mouseY = 0;
        this.clock = new THREE.Clock();

        // 加载管理器
        this.loadingManager = new THREE.LoadingManager();
        this.loader = new THREE.GLTFLoader(this.loadingManager);
        this.textureLoader = new THREE.TextureLoader(this.loadingManager);

        // 控制变量
        this.controls = {
            rotateSpeed: 0.002,
            zoomSpeed: 0.1,
            moveSpeed: 0.5,
            isRotating: false,
            isMoving: false,
            lastX: 0,
            lastY: 0,
            targetPosition: new THREE.Vector3(),
            autoRotate: true,
            autoRotateSpeed: 0.2,
            minDistance: 10,
            maxDistance: 200,
            keys: {
                up: false,
                down: false,
                left: false,
                right: false,
                forward: false,
                backward: false
            }
        };

        // 设置更亮的背景色
        this.renderer.setClearColor(0x0a0a1a, 1);

        this.init();
        this.initControls();
        this.animate();
    }

    init() {
        // 设置渲染器
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.shadowMap.enabled = true;
        this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

        // 相机初始位置
        this.camera.position.set(0, 15, 50);
        this.camera.lookAt(this.scene.position);

        // 添加更亮的星空背景
        this.createStars();

        // 添加小王子家的星球
        this.createHomePlanet();

        // 添加小王子
        this.createLittlePrince();

        // 添加其他用户星球
        this.createUserPlanets();

        // 添加增强的光源
        this.createEnhancedLights();

        // 设置交互
        this.setupInteractions();
    }

    createLittlePrince() {
        this.loader.load('static/models/prince.glb',
            (gltf) => {
                console.log("✅ 小王子模型加载成功");
                const prince = gltf.scene;

                // 设置小王子属性
                prince.scale.set(2.5 * 0.436, 2.5 * 0.663, 2.5 * 1); // (1.09, 1.6575, 2.5)
                prince.position.set(
                    0,
                    0,
                    19.38/2 + 2.5/2 // 星球顶部(z=9.69) + 半身高(1.25) = 10.94
                );
                prince.rotation.y = Math.PI/4; // 45度面向斜前方
                prince.userData = { target: 'resources' };

                // 增强模型可见性
                prince.traverse((child) => {
                    if (child.isMesh) {
                        child.material.emissive = new THREE.Color(0x333333);
                        child.material.emissiveIntensity = 0.3;
                        child.material.shininess = 50;
                        child.castShadow = true;
                        child.receiveShadow = true;
                    }
                });

                // 动画设置
                this.mixer = new THREE.AnimationMixer(prince);
                const clip = gltf.animations[0];
                if (clip) {
                    const action = this.mixer.clipAction(clip);
                    action.play();
                }

                this.scene.add(prince);
                this.prince = prince;
            },
            undefined,
            (err) => {
                console.error("❌ 小王子模型加载失败：", err);
            }
        );
    }

    createHomePlanet() {
        this.loader.load('static/models/planet.glb', (gltf) => {
            const planet = gltf.scene;
            planet.scale.set(20 * 1, 20 * 0.996, 20 * 0.969); // (20, 19.92, 19.38)
            planet.position.set(0, 0, 0);
            planet.rotation.set(0, 0, 0); // 无旋转

            // 增强星球可见性
            planet.traverse((child) => {
                if (child.isMesh) {
                    child.material.emissive = new THREE.Color(0x222222);
                    child.material.emissiveIntensity = 0.5;
                    child.material.shininess = 100;
                    child.castShadow = true;
                    child.receiveShadow = true;
                }
            });

            this.addHomeElements(planet);
            this.scene.add(planet);
            this.homePlanet = planet;
        });
    }

    addHomeElements(planet) {
        // 玫瑰花 - 匿名发帖
        this.loader.load('static/models/rose.glb', (gltf) => {
            const rose = gltf.scene;
            rose.scale.set(1.8 * 0.48, 1.8 * 0.585, 1.8 * 1); // (0.864, 1.053, 1.8)
            rose.position.set(
            20/2 * Math.cos(THREE.MathUtils.degToRad(30)) * 1.02, // x=8.66
            19.92/2 * Math.sin(THREE.MathUtils.degToRad(30)) * 1.02, // y=4.98
            19.38/2 * Math.sin(THREE.MathUtils.degToRad(20)) * 1.02 // z=3.31
            );
            rose.rotation.y = -Math.PI/4; // -45度叶片朝外
            rose.userData = { target: 'new_post' };

            // 增强玫瑰可见性
            rose.traverse((child) => {
                if (child.isMesh) {
                    child.material.emissive = new THREE.Color(0x550000);
                    child.material.emissiveIntensity = 0.3;
                }
            });

            planet.add(rose);
        });

        // 狐狸 - AI助手
        this.loader.load('static/models/fox.glb', (gltf) => {
            const fox = gltf.scene;
            fox.scale.set(2.0 * 0.93, 2.0 * 0.765, 2.0 * 1); // (1.86, 1.53, 2.0)
            fox.position.set(
            -20/2 * Math.cos(THREE.MathUtils.degToRad(35)) * 1.03, // x=-8.19
            19.92/2 * Math.sin(THREE.MathUtils.degToRad(35)) * 1.03, // y=5.71
            19.38/2 * Math.sin(THREE.MathUtils.degToRad(15)) * 1.03 // z=2.57
            );
            fox.rotation.y = Math.PI/3; // 60度面向星球中心
            fox.userData = { target: 'chatbot' };

            // 增强狐狸可见性
            fox.traverse((child) => {
                if (child.isMesh) {
                    child.material.emissive = new THREE.Color(0x333300);
                    child.material.emissiveIntensity = 0.3;
                }
            });

            planet.add(fox);
        });

        // 树苗 - 日记本
        this.loader.load('static/models/tree.glb', (gltf) => {
            const tree = gltf.scene;
            tree.scale.set(2.2 * 0.96, 2.2 * 1, 2.2 * 0.902); // (2.112, 2.2, 1.9844)
            tree.position.set(
            0,
            19.92/2 * 0.8, // y=7.968
            -19.38/2 * 0.7  // z=-6.783
            );
            tree.rotation.set(0, 0, 0); // 无旋转
            tree.userData = { target: 'diary' };

            // 增强树苗可见性
            tree.traverse((child) => {
                if (child.isMesh) {
                    child.material.emissive = new THREE.Color(0x003300);
                    child.material.emissiveIntensity = 0.3;
                }
            });

            planet.add(tree);
        });
    }

    createUserPlanets() {
        const postElements = document.querySelectorAll('.post-data');
        const posts = Array.from(postElements).map(el => ({
            id: el.dataset.id,
            content: el.dataset.content,
            sentiment: el.dataset.sentiment,
            date: el.dataset.date,
            commentCount: el.dataset.comments
        }));

        const colors = {
            positive: 0x88ff88,
            neutral: 0xffff88,
            negative: 0xff8888
        };

        const beltRadius = 20;
        const beltWidth = 30;

        posts.forEach((post, index) => {
            const geometry = new THREE.SphereGeometry(0.5 + Math.random() * 1.5, 32, 32);
            const material = new THREE.MeshPhongMaterial({
                color: colors[post.sentiment] || colors.neutral,
                shininess: 50,
                emissive: colors[post.sentiment] || colors.neutral,
                emissiveIntensity: 0.2
            });

            const planet = new THREE.Mesh(geometry, material);
            planet.castShadow = true;
            planet.receiveShadow = true;

            const angle = Math.random() * Math.PI * 2;
            const distance = beltRadius + Math.random() * beltWidth;
            const height = (Math.random() - 0.5) * 10;

            planet.position.x = Math.cos(angle) * distance;
            planet.position.y = height;
            planet.position.z = Math.sin(angle) * distance;

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
                orbitAngle: angle
            };

            if (post.commentCount > 5) {
                this.addPlanetRing(planet);
            }

            this.scene.add(planet);
            this.planets.push(planet);
        });
    }

    addPlanetRing(planet) {
        const ringInnerRadius = planet.geometry.parameters.radius * 1.5;
        const ringOuterRadius = planet.geometry.parameters.radius * 2.5;
        const ringGeometry = new THREE.RingGeometry(ringInnerRadius, ringOuterRadius, 32);
        ringGeometry.rotateX(Math.PI / 2);

        const ringMaterial = new THREE.MeshPhongMaterial({
            color: 0xcccccc,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.7,
            emissive: 0xcccccc,
            emissiveIntensity: 0.1
        });

        const ring = new THREE.Mesh(ringGeometry, ringMaterial);
        planet.add(ring);
    }

    createStars() {
        const geometry = new THREE.BufferGeometry();
        const vertices = [];
        const colors = [];
        const sizes = [];

        for (let i = 0; i < 10000; i++) {
            const x = (Math.random() - 0.5) * 2000;
            const y = (Math.random() - 0.5) * 2000;
            const z = (Math.random() - 0.5) * 2000;
            vertices.push(x, y, z);

            const colorIntensity = 0.8 + Math.random() * 0.2;
            colors.push(colorIntensity, colorIntensity, colorIntensity);

            sizes.push(0.5 + Math.random() * 2);
        }

        geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
        geometry.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));

        const material = new THREE.PointsMaterial({
            size: 1.5,
            sizeAttenuation: true,
            color: 0xffffff,
            vertexColors: true,
            transparent: true,
            opacity: 1,
            blending: THREE.AdditiveBlending
        });

        this.stars = new THREE.Points(geometry, material);
        this.scene.add(this.stars);
    }

    createEnhancedLights() {
        // 更强的环境光
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
        this.scene.add(ambientLight);

        // 主光源
        const directionalLight = new THREE.DirectionalLight(0xffffff, 1.2);
        directionalLight.position.set(5, 10, 7);
        directionalLight.castShadow = true;
        directionalLight.shadow.mapSize.width = 2048;
        directionalLight.shadow.mapSize.height = 2048;
        this.scene.add(directionalLight);

        // 补光1
        const fillLight1 = new THREE.DirectionalLight(0xffffff, 0.5);
        fillLight1.position.set(-5, 3, -5);
        this.scene.add(fillLight1);

        // 补光2
        const fillLight2 = new THREE.DirectionalLight(0xffffff, 0.3);
        fillLight2.position.set(0, -10, 0);
        this.scene.add(fillLight2);

        // 中心点光源
        const pointLight = new THREE.PointLight(0xffffee, 2, 200);
        pointLight.position.set(0, 30, 0);
        pointLight.castShadow = true;
        this.scene.add(pointLight);

        // 辅助光源可视化
        const pointLightHelper = new THREE.PointLightHelper(pointLight, 5);
        this.scene.add(pointLightHelper);
    }

    setupInteractions() {
        document.addEventListener('mousemove', (event) => {
            this.mouseX = (event.clientX - window.innerWidth / 2) * 0.005;
            this.mouseY = (event.clientY - window.innerHeight / 2) * 0.005;
        });

        document.addEventListener('click', (event) => {
            const mouse = new THREE.Vector2(
                (event.clientX / window.innerWidth) * 2 - 1,
                -(event.clientY / window.innerHeight) * 2 + 1
            );

            const raycaster = new THREE.Raycaster();
            raycaster.setFromCamera(mouse, this.camera);

            if (this.prince) {
                const princeIntersects = raycaster.intersectObject(this.prince, true);
                if (princeIntersects.length > 0 && this.prince.userData && this.prince.userData.target) {
                    window.location.href = `/${this.prince.userData.target}`;
                    return;
                }
            }

            if (this.homePlanet) {
                const homeIntersects = raycaster.intersectObjects(this.homePlanet.children, true);
                if (homeIntersects.length > 0) {
                    const element = homeIntersects[0].object;
                    let targetObj = element;
                    while (targetObj && !targetObj.userData?.target && targetObj.parent) {
                        targetObj = targetObj.parent;
                    }

                    if (targetObj.userData && targetObj.userData.target) {
                        window.location.href = `/${targetObj.userData.target}`;
                        return;
                    }
                }
            }

            const planetIntersects = raycaster.intersectObjects(this.planets);
            if (planetIntersects.length > 0) {
                const planet = planetIntersects[0].object;
                window.location.href = `/post/${planet.userData.postId}`;
                return;
            }
        });

        window.addEventListener('resize', () => {
            this.camera.aspect = window.innerWidth / window.innerHeight;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(window.innerWidth, window.innerHeight);
        });

        document.addEventListener('mousemove', (event) => {
            const mouse = new THREE.Vector2(
                (event.clientX / window.innerWidth) * 2 - 1,
                -(event.clientY / window.innerHeight) * 2 + 1
            );

            const raycaster = new THREE.Raycaster();
            raycaster.setFromCamera(mouse, this.camera);

            if (this.prince) this.prince.children.forEach(child => child.material?.emissive?.setHex(0x333333));
            if (this.homePlanet) this.homePlanet.children.forEach(child => {
                if (child.material) {
                    child.material.emissive?.setHex(0x222222);
                    child.material.emissiveIntensity = 0.5;
                }
            });

            let hovered = false;

            if (this.prince) {
                const intersects = raycaster.intersectObject(this.prince, true);
                if (intersects.length > 0) {
                    intersects[0].object.material?.emissive?.setHex(0x666666);
                    hovered = true;
                }
            }

            if (this.homePlanet && !hovered) {
                const intersects = raycaster.intersectObjects(this.homePlanet.children, true);
                if (intersects.length > 0) {
                    const obj = intersects[0].object;
                    if (obj.material) {
                        obj.material.emissive?.setHex(0x666666);
                        obj.material.emissiveIntensity = 0.8;
                    }
                    hovered = true;
                }
            }

            document.body.style.cursor = hovered ? 'pointer' : 'default';
        });
    }

    initControls() {
        const el = this.renderer?.domElement || document.getElementById('galaxy-canvas');
        if (!el) return;

        // 鼠标控制
        el.addEventListener('mousedown', (e) => {
            this.controls.isRotating = e.button === 0;
            this.controls.isMoving = e.button === 2;
            this.controls.lastX = e.clientX;
            this.controls.lastY = e.clientY;
            this.controls.autoRotate = false;
        });

        window.addEventListener('mouseup', () => {
            this.controls.isRotating = false;
            this.controls.isMoving = false;
        });

        el.addEventListener('mousemove', (e) => {
            const deltaX = e.clientX - this.controls.lastX;
            const deltaY = e.clientY - this.controls.lastY;

            if (this.controls.isRotating) {
                const theta = deltaX * this.controls.rotateSpeed;
                const phi = deltaY * this.controls.rotateSpeed;

                const radius = this.camera.position.distanceTo(this.scene.position);
                const spherical = new THREE.Spherical();
                spherical.setFromVector3(this.camera.position);

                spherical.theta -= theta;
                spherical.phi = THREE.MathUtils.clamp(spherical.phi - phi, 0.1, Math.PI - 0.1);

                this.camera.position.setFromSpherical(spherical).add(this.scene.position);
                this.camera.lookAt(this.scene.position);
            }

            this.controls.lastX = e.clientX;
            this.controls.lastY = e.clientY;
        });

        // 鼠标滚轮缩放（仍然在 canvas 上）
        el.addEventListener('wheel', (e) => {
            e.preventDefault();
            const direction = e.deltaY > 0 ? 1 : -1;
            const zoomFactor = 1 + direction * this.controls.zoomSpeed;

            const newPosition = this.camera.position.clone()
                .sub(this.scene.position)
                .multiplyScalar(zoomFactor)
                .add(this.scene.position);

            const distance = newPosition.distanceTo(this.scene.position);
            if (distance > this.controls.minDistance && distance < this.controls.maxDistance) {
                this.camera.position.copy(newPosition);
            }
        }, { passive: false });

        // 键盘控制（只绑定 window，不要用 document，避免冲突）
        window.addEventListener('keydown', (e) => {
            switch(e.key.toLowerCase()) {
                case 'w': this.controls.keys.forward = true; break;
                case 's': this.controls.keys.backward = true; break;
                case 'a': this.controls.keys.left = true; break;
                case 'd': this.controls.keys.right = true; break;
                case 'q': this.controls.keys.up = true; break;
                case 'e': this.controls.keys.down = true; break;
                case 'r': this.controls.autoRotate = !this.controls.autoRotate; break;
            }
        });

        window.addEventListener('keyup', (e) => {
            switch(e.key.toLowerCase()) {
                case 'w': this.controls.keys.forward = false; break;
                case 's': this.controls.keys.backward = false; break;
                case 'a': this.controls.keys.left = false; break;
                case 'd': this.controls.keys.right = false; break;
                case 'q': this.controls.keys.up = false; break;
                case 'e': this.controls.keys.down = false; break;
            }
        });

        // 禁用右键菜单，仅限 canvas 内部
        el.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });
    }


    handleKeyboardMovement(delta) {
        const moveSpeed = this.controls.moveSpeed * delta * 60;
        const direction = new THREE.Vector3();
        const side = new THREE.Vector3();
        const up = new THREE.Vector3(0, 1, 0);

        this.camera.getWorldDirection(direction);
        direction.normalize();
        side.crossVectors(direction, up).normalize();

        if (this.controls.keys.forward) {
            this.camera.position.addScaledVector(direction, moveSpeed);
        }
        if (this.controls.keys.backward) {
            this.camera.position.addScaledVector(direction, -moveSpeed);
        }
        if (this.controls.keys.left) {
            this.camera.position.addScaledVector(side, -moveSpeed);
        }
        if (this.controls.keys.right) {
            this.camera.position.addScaledVector(side, moveSpeed);
        }
        if (this.controls.keys.up) {
            this.camera.position.addScaledVector(up, moveSpeed);
        }
        if (this.controls.keys.down) {
            this.camera.position.addScaledVector(up, -moveSpeed);
        }

        this.camera.lookAt(this.scene.position);
    }

    animate() {
        requestAnimationFrame(() => this.animate());

        const delta = this.clock.getDelta();

        // 处理键盘移动
        this.handleKeyboardMovement(delta);

        // 自动旋转
        if (this.controls.autoRotate) {
            const radius = this.camera.position.distanceTo(this.scene.position);
            const spherical = new THREE.Spherical();
            spherical.setFromVector3(this.camera.position);

            spherical.theta += this.controls.autoRotateSpeed * delta;
            spherical.phi = THREE.MathUtils.clamp(spherical.phi, 0.1, Math.PI - 0.1);

            this.camera.position.setFromSpherical(spherical).add(this.scene.position);
            this.camera.lookAt(this.scene.position);
        }

        // 更新动画
        if (this.mixer) this.mixer.update(delta);

        // 行星动画
        this.planets.forEach(planet => {
            planet.rotation.x += planet.userData.rotationSpeed.x;
            planet.rotation.y += planet.userData.rotationSpeed.y;
            planet.rotation.z += planet.userData.rotationSpeed.z;

            planet.userData.orbitAngle += planet.userData.orbitSpeed;
            planet.position.x = Math.cos(planet.userData.orbitAngle) * planet.userData.orbitRadius;
            planet.position.z = Math.sin(planet.userData.orbitAngle) * planet.userData.orbitRadius;

            planet.position.y = planet.userData.orbitHeight + Math.sin(this.clock.getElapsedTime() + planet.userData.orbitAngle) * 0.5;
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

// 初始化
document.addEventListener('DOMContentLoaded', function () {
  const canvas = document.getElementById('galaxy-canvas');
  if (!canvas) {
    // 本页没有星空画布，跳过初始化，避免全局事件监听影响表单输入
    return;
  }
  try {
    window._littlePrince = new LittlePrinceGalaxy();
  } catch (e) {
    console.error('LittlePrince init failed:', e);
  }
});

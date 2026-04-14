#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NSGA-II算法解决5架无人机协同干扰问题 - 多核CPU优化版
"""
import numpy as np
import math
import random
import json
import time
import pandas as pd
import multiprocessing as mp
from typing import List, Dict, Tuple, Any
from dataclasses import dataclass

# 设置随机种子
random.seed(42)
np.random.seed(42)

# ==================== 常量定义 ====================
g = 9.8  # 重力加速度 (m/s²)
vs = 3.0  # 烟雾下沉速度 (m/s)
Rc = 10.0  # 烟雾干扰球半径 (m)
Teff = 20.0  # 烟雾有效时间 (秒)
CYL_RADIUS = 7.0  # 圆柱体半径 (m)
CYL_HEIGHT = 10.0  # 圆柱体高度 (m)
CYL_CENTER = np.array([0.0, 200.0, 0.0])  # 圆柱体圆心

# ==================== 严格按照题目给出的坐标 ====================
MISSILES = {
    'M1': np.array([20000.0, 0.0, 2000.0]),
    'M2': np.array([19000.0, 600.0, 2100.0]),
    'M3': np.array([18000.0, -600.0, 1900.0])
}

DRONES = {
    'FY1': np.array([17800.0, 0.0, 1800.0]),
    'FY2': np.array([12000.0, 1400.0, 1400.0]),
    'FY3': np.array([6000.0, -3000.0, 700.0]),
    'FY4': np.array([11000.0, 2000.0, 1800.0]),
    'FY5': np.array([13000.0, -2000.0, 1300.0])
}

MISSILE_SPEED = 300.0  # 导弹速度 (m/s)
SIMULATION_END = 100.0  # 延长模拟时间 (s)
DT = 0.05  # 减小时间步长，提高精度 (s)


# ==================== 工具函数 ====================
def get_missile_velocity(missile_pos: np.ndarray) -> np.ndarray:
    """计算导弹指向原点(0,0,0)的速度向量"""
    target = np.array([0.0, 0.0, 0.0])
    direction = target - missile_pos
    direction = direction / (np.linalg.norm(direction) + 1e-10)
    return direction * MISSILE_SPEED


def optimized_target_points(n_angle: int = 20, n_height: int = 8) -> np.ndarray:
    """优化采样点分布 - 增加关键区域密度"""
    pts = []
    # 分层采样：底部和顶部更密集
    heights = np.concatenate([
        np.linspace(0, 2, 4),  # 底部密集
        np.linspace(2, 8, 4),  # 中部
        np.linspace(8, 10, 4)  # 顶部密集
    ])

    angles = np.linspace(0, 2 * math.pi, n_angle, endpoint=False)

    for z in heights:
        # 中心点（非常重要！）
        pts.append(np.array([CYL_CENTER[0], CYL_CENTER[1], CYL_CENTER[2] + z]))

        # 表面点
        for ang in angles:
            x = CYL_CENTER[0] + CYL_RADIUS * math.cos(ang)
            y = CYL_CENTER[1] + CYL_RADIUS * math.sin(ang)
            pts.append(np.array([x, y, CYL_CENTER[2] + z]))

    # 添加边缘关键点
    for ang in angles[::4]:  # 每隔4个角度取一个
        x = CYL_CENTER[0] + CYL_RADIUS * math.cos(ang)
        y = CYL_CENTER[1] + CYL_RADIUS * math.sin(ang)
        pts.append(np.array([x, y, CYL_CENTER[2]]))  # 底部边缘
        pts.append(np.array([x, y, CYL_CENTER[2] + 10.0]))  # 顶部边缘

    return np.array(pts)


def missile_position(t: float, missile_init: np.ndarray, missile_vel: np.ndarray) -> np.ndarray:
    """计算导弹在时间t的位置"""
    return missile_init + t * missile_vel


def is_occluded(M: np.ndarray, P: np.ndarray, C: np.ndarray, Rc: float = 10.0) -> bool:
    """正确的遮蔽判定：点C到直线MP的距离 ≤ Rc"""
    MP = P - M
    MC = C - M

    if np.linalg.norm(MP) < 1e-6:
        return np.linalg.norm(MC) <= Rc

    # 计算点到直线的距离
    distance = np.linalg.norm(np.cross(MC, MP)) / np.linalg.norm(MP)
    return distance <= Rc


def quick_visibility_check(M: np.ndarray, P: np.ndarray, C: np.ndarray, Rc: float = 10.0) -> bool:
    """快速预筛选：排除明显不可能遮蔽的情况"""
    MP = P - M
    MC = C - M

    # 1. 距离筛选
    distance = np.linalg.norm(np.cross(MC, MP)) / np.linalg.norm(MP)
    if distance > Rc + 15.0:  # 适当放宽阈值
        return False

    # 2. 方向筛选：烟幕应该在视线前方
    t = np.dot(MC, MP) / (np.dot(MP, MP) + 1e-10)
    if t < -0.3 or t > 1.3:  # 适当放宽范围
        return False

    return True


# ==================== 无人机策略类 ====================
class DroneStrategy:
    """单个无人机的投放策略"""

    def __init__(self, drone_name: str, alpha: float, v: float,
                 release_times: List[float], fuse_delays: List[float]):
        self.drone_name = drone_name
        self.alpha = alpha
        self.v = v
        self.release_times = sorted(release_times)
        self.fuse_delays = fuse_delays
        self.drone_pos = DRONES[drone_name]
        self.u = np.array([math.cos(alpha), math.sin(alpha), 0.0])

    def get_smoke_windows(self, T_end: float = SIMULATION_END) -> List[Tuple]:
        """计算该无人机的烟幕时间窗口"""
        windows = []

        for tr, tu in zip(self.release_times, self.fuse_delays):
            # 投放点位置
            release_point = self.drone_pos + self.v * tr * self.u
            release_point[2] = self.drone_pos[2]

            # 爆炸点位置（精确计算）
            horizontal_displacement = self.v * tu * self.u
            vertical_displacement = np.array([0.0, 0.0, -0.5 * g * tu * tu])
            explosion_point = release_point + horizontal_displacement + vertical_displacement

            if explosion_point[2] <= 0.5:
                continue  # 忽略过低爆炸点

            Te = tr + tu
            # 精确计算烟幕有效时间
            sink_time = explosion_point[2] / vs
            Tend = Te + min(Teff, sink_time)

            # 只添加在模拟时间范围内的窗口
            if Te <= T_end:
                windows.append((Te, Tend, explosion_point, release_point))

        return windows


# ==================== 并行评估函数 ====================
def evaluate_chromosome_wrapper(args):
    """包装函数用于多进程评估"""
    chromosome, bounds = args
    return _evaluate_chromosome(chromosome, bounds)


def _evaluate_chromosome(chromosome, bounds):
    """独立的评估函数，避免pickle问题"""
    # 解码染色体
    strategies = []
    drone_names = ['FY1', 'FY2', 'FY3', 'FY4', 'FY5']

    for i in range(5):
        start_idx = i * 8
        alpha = chromosome[start_idx]
        v = chromosome[start_idx + 1]
        t1 = max(0.0, chromosome[start_idx + 2])
        dt12 = max(1.0, chromosome[start_idx + 3])
        dt23 = max(1.0, chromosome[start_idx + 4])
        tau1 = max(0.0, chromosome[start_idx + 5])
        tau2 = max(0.0, chromosome[start_idx + 6])
        tau3 = max(0.0, chromosome[start_idx + 7])

        release_times = sorted([t1, t1 + dt12, t1 + dt12 + dt23])
        fuse_delays = [tau1, tau2, tau3]

        strategies.append(DroneStrategy(drone_names[i], alpha, v, release_times, fuse_delays))

    # 计算惩罚值
    total_penalty = 0.0
    for strategy in strategies:
        times = strategy.release_times
        for i in range(1, len(times)):
            if times[i] - times[i - 1] < 1.0:
                total_penalty += 10000.0 * (1.0 - (times[i] - times[i - 1]))

        if not (70.0 <= strategy.v <= 140.0):
            total_penalty += 10000.0

    # 计算遮蔽时间
    missile_times = calculate_occlusion_times(strategies)

    # 动态权重
    min_time = min(missile_times.values()) if missile_times else 0
    weights = {missile: 2.0 if time == min_time else 1.0
               for missile, time in missile_times.items()}

    objectives = (
        -missile_times['M1'] * weights['M1'],
        -missile_times['M2'] * weights['M2'],
        -missile_times['M3'] * weights['M3']
    )

    return Solution(chromosome, objectives, total_penalty)


def calculate_occlusion_times(strategies: List[DroneStrategy]) -> Dict[str, float]:
    """遮蔽时间计算函数"""
    # 预计算导弹轨迹
    missile_trajectories = {}
    time_points = np.arange(0.0, SIMULATION_END + 1e-9, DT)

    for missile_name, missile_init in MISSILES.items():
        missile_vel = get_missile_velocity(missile_init)
        trajectory = [missile_position(t, missile_init, missile_vel) for t in time_points]
        missile_trajectories[missile_name] = trajectory

    # 获取所有烟幕时间窗口
    all_windows = []
    for strategy in strategies:
        windows = strategy.get_smoke_windows()
        all_windows.extend(windows)

    if not all_windows:
        return {'M1': 0.0, 'M2': 0.0, 'M3': 0.0}

    missile_occlusion = {missile: 0.0 for missile in MISSILES.keys()}
    target_pts = optimized_target_points(20, 8)

    # 时间步进计算
    for t_idx, t in enumerate(time_points):
        active_smoke = []
        for Te, Tend, explosion_point, _ in all_windows:
            if Te <= t <= Tend:
                sink_dist = vs * (t - Te)
                cloud_center = explosion_point + np.array([0, 0, -sink_dist])
                if cloud_center[2] >= 0.5:
                    active_smoke.append(cloud_center)

        if not active_smoke:
            continue

        # 对每个导弹检查遮蔽
        for missile_name in MISSILES.keys():
            M = missile_trajectories[missile_name][t_idx]

            # 检查所有目标点是否都被遮蔽
            all_occluded = True
            for P in target_pts:
                point_occluded = False

                # 快速预筛选
                for C in active_smoke:
                    if not quick_visibility_check(M, P, C, Rc):
                        continue

                    if is_occluded(M, P, C, Rc):
                        point_occluded = True
                        break

                if not point_occluded:
                    all_occluded = False
                    break

            if all_occluded:
                missile_occlusion[missile_name] += DT

    return missile_occlusion


# ==================== NSGA-II 核心算法 ====================
@dataclass
class Solution:
    chromosome: np.ndarray
    objectives: Tuple[float, float, float]
    penalty: float
    rank: int = 0
    crowding_distance: float = 0.0
    total_occlusion: float = 0.0
    min_occlusion: float = 0.0
    balance_score: float = 0.0


class NSGA2Optimizer:
    def __init__(self, pop_size=100, max_gens=300, crossover_rate=0.9, mutation_rate=0.15, n_workers=None):
        self.pop_size = pop_size
        self.max_gens = max_gens
        self.crossover_rate = crossover_rate
        self.mutation_rate = mutation_rate
        self.dim = 40
        self.best_solutions = []
        self.gen = 0

        # 多核并行设置
        self.n_workers = n_workers or max(1, mp.cpu_count() - 2)  # 留2个核心给系统
        print(f"使用 {self.n_workers} 个CPU核心进行并行计算")

        # 变量边界
        self.bounds = []
        for _ in range(5):
            self.bounds.extend([
                (0.0, 2.0 * math.pi, True),
                (70.0, 140.0, False),
                (0.0, 30.0, False),
                (1.0, 15.0, False),
                (1.0, 15.0, False),
                (0.0, 15.0, False),
                (0.0, 15.0, False),
                (0.0, 15.0, False)
            ])

    def initialize_population(self):
        """改进的种群初始化 - 增加多样性"""
        population = []
        for i in range(self.pop_size):
            chromo = np.zeros(self.dim)
            for d in range(self.dim):
                lo, hi, wrap = self.bounds[d]

                if i < self.pop_size * 0.3:
                    drone_idx = d // 8
                    drone_name = ['FY1', 'FY2', 'FY3', 'FY4', 'FY5'][drone_idx]
                    drone_height = DRONES[drone_name][2]

                    if d % 8 == 1:  # 速度参数
                        chromo[d] = random.uniform(100, 140) if drone_height > 1500 else random.uniform(70, 140)
                    elif d % 8 == 2:  # 第一个投放时间
                        chromo[d] = random.uniform(5, 25)
                    elif d % 8 in [5, 6, 7]:  # 引信延时
                        chromo[d] = random.uniform(3, 12)
                    else:
                        chromo[d] = random.uniform(lo, hi)
                else:
                    chromo[d] = random.uniform(lo, hi)

            solution = self.evaluate_solution(chromo)
            population.append(solution)
        return population

    def evaluate_solution(self, chromosome: np.ndarray) -> Solution:
        """评估解的质量"""
        return _evaluate_chromosome(chromosome, self.bounds)

    def evaluate_population_parallel(self, chromosomes):
        """并行评估种群"""
        with mp.Pool(processes=self.n_workers) as pool:
            args = [(chromo, self.bounds) for chromo in chromosomes]
            results = pool.map(evaluate_chromosome_wrapper, args)
        return results

    def decode_chromosome(self, chromosome: np.ndarray) -> List[DroneStrategy]:
        """解码染色体"""
        strategies = []
        drone_names = ['FY1', 'FY2', 'FY3', 'FY4', 'FY5']

        for i in range(5):
            start_idx = i * 8
            alpha = chromosome[start_idx]
            v = chromosome[start_idx + 1]
            t1 = max(0.0, chromosome[start_idx + 2])
            dt12 = max(1.0, chromosome[start_idx + 3])
            dt23 = max(1.0, chromosome[start_idx + 4])
            tau1 = max(0.0, chromosome[start_idx + 5])
            tau2 = max(0.0, chromosome[start_idx + 6])
            tau3 = max(0.0, chromosome[start_idx + 7])

            release_times = sorted([t1, t1 + dt12, t1 + dt12 + dt23])
            fuse_delays = [tau1, tau2, tau3]

            strategies.append(DroneStrategy(drone_names[i], alpha, v, release_times, fuse_delays))

        return strategies

    def fast_non_dominated_sort(self, population: List[Solution]) -> List[List[Solution]]:
        """快速非支配排序"""
        fronts = [[]]
        for p in population:
            p.dominated_set = []
            p.domination_count = 0

            for q in population:
                if self.dominates(p, q):
                    p.dominated_set.append(q)
                elif self.dominates(q, p):
                    p.domination_count += 1

            if p.domination_count == 0:
                p.rank = 0
                fronts[0].append(p)

        i = 0
        while fronts[i]:
            next_front = []
            for p in fronts[i]:
                for q in p.dominated_set:
                    q.domination_count -= 1
                    if q.domination_count == 0:
                        q.rank = i + 1
                        next_front.append(q)
            i += 1
            fronts.append(next_front)

        return fronts

    def dominates(self, a: Solution, b: Solution) -> bool:
        """判断解a是否支配解b"""
        if a.penalty > 0 and b.penalty == 0:
            return False
        if a.penalty == 0 and b.penalty > 0:
            return True

        better_in_all = True
        better_in_one = False

        for i in range(3):
            if a.objectives[i] > b.objectives[i]:
                better_in_all = False
            elif a.objectives[i] < b.objectives[i]:
                better_in_one = True

        return better_in_all and better_in_one

    def crowding_distance_assignment(self, front: List[Solution]):
        """计算拥挤度距离"""
        if not front:
            return

        n = len(front)
        for solution in front:
            solution.crowding_distance = 0.0

        for m in range(3):
            front.sort(key=lambda x: x.objectives[m])
            front[0].crowding_distance = float('inf')
            front[-1].crowding_distance = float('inf')

            f_min = front[0].objectives[m]
            f_max = front[-1].objectives[m]

            if f_max - f_min < 1e-10:
                continue

            for i in range(1, n - 1):
                front[i].crowding_distance += (
                        (front[i + 1].objectives[m] - front[i - 1].objectives[m]) / (f_max - f_min)
                )

    def selection(self, population: List[Solution]) -> List[Solution]:
        """改进的锦标赛选择"""
        selected = []
        tournament_size = 3

        for _ in range(self.pop_size):
            tournament = random.sample(population, tournament_size)
            best = min(tournament, key=lambda x: (x.penalty, x.rank, -x.crowding_distance))
            selected.append(best)

        return selected

    def adaptive_crossover(self, parent1: Solution, parent2: Solution) -> Solution:
        """自适应交叉"""
        child_chromo = np.zeros(self.dim)

        current_cr = self.crossover_rate * (1 - self.gen / self.max_gens * 0.3)

        for i in range(self.dim):
            if random.random() < current_cr:
                u = random.random()
                if u <= 0.5:
                    beta = (2 * u) ** (1 / (1 + 2.0))
                else:
                    beta = (1 / (2 * (1 - u))) ** (1 / (1 + 2.0))

                child_chromo[i] = 0.5 * (
                        (1 + beta) * parent1.chromosome[i] +
                        (1 - beta) * parent2.chromosome[i]
                )
            else:
                child_chromo[i] = parent1.chromosome[i] if random.random() < 0.5 else parent2.chromosome[i]

        return Solution(child_chromo, (0, 0, 0), 0)  # 返回未评估的解

    def adaptive_mutation(self, individual: Solution) -> Solution:
        """自适应变异"""
        mutant_chromo = individual.chromosome.copy()

        current_mr = self.mutation_rate * (1 + self.gen / self.max_gens * 0.5)

        for i in range(self.dim):
            if random.random() < current_mr:
                lo, hi, wrap = self.bounds[i]

                if wrap:
                    L = hi - lo
                    delta = random.uniform(-0.15, 0.15) * L
                    mutant_chromo[i] = lo + ((mutant_chromo[i] - lo + delta) % L)
                else:
                    delta = random.uniform(-0.15, 0.15) * (hi - lo)
                    mutant_chromo[i] += delta
                    mutant_chromo[i] = max(lo, min(hi, mutant_chromo[i]))

        return Solution(mutant_chromo, (0, 0, 0), 0)  # 返回未评估的解

    def optimize(self):
        """主优化循环 - 并行版本"""
        population = self.initialize_population()
        self.best_solutions = []

        for gen in range(self.max_gens):
            self.gen = gen

            # 非支配排序
            fronts = self.fast_non_dominated_sort(population)

            # 保存精英解
            if fronts[0]:
                self.best_solutions.extend(fronts[0])
                if len(self.best_solutions) > 120:
                    self.best_solutions.sort(key=lambda x: (x.penalty, sum(-obj for obj in x.objectives)))
                    self.best_solutions = self.best_solutions[:120]

            # 计算拥挤度
            for front in fronts:
                self.crowding_distance_assignment(front)

            # 选择
            selected = self.selection(population)

            # 交叉和变异
            offspring_chromosomes = []
            for i in range(0, len(selected), 2):
                if i + 1 < len(selected):
                    child1 = self.adaptive_crossover(selected[i], selected[i + 1])
                    child2 = self.adaptive_crossover(selected[i + 1], selected[i])
                    offspring_chromosomes.extend([child1.chromosome, child2.chromosome])

            # 并行评估所有后代
            if offspring_chromosomes:
                evaluated_offspring = self.evaluate_population_parallel(offspring_chromosomes)
            else:
                evaluated_offspring = []

            # 环境选择
            combined = population + evaluated_offspring
            fronts = self.fast_non_dominated_sort(combined)

            new_population = []
            current_size = 0
            for front in fronts:
                if current_size + len(front) <= self.pop_size:
                    new_population.extend(front)
                    current_size += len(front)
                else:
                    self.crowding_distance_assignment(front)
                    front.sort(key=lambda x: x.crowding_distance, reverse=True)
                    new_population.extend(front[:self.pop_size - current_size])
                    break

            population = new_population

            # 输出进度
            if gen % 10 == 0:
                self.print_progress(gen, fronts[0] if fronts else [])

        return fronts[0] if fronts else population

    def print_progress(self, gen: int, pareto_front: List[Solution]):
        """输出优化进度和Excel表格中的所有信息"""
        if not pareto_front:
            print(f"Gen {gen}: 无Pareto前沿解")
            return

        # 选择当前最优解
        best_solution = self.select_best_solution_for_display(pareto_front)
        strategies = self.decode_chromosome(best_solution.chromosome)

        # 计算遮蔽时间
        missile_occlusion = calculate_occlusion_times(strategies)
        total_occlusion = sum(missile_occlusion.values())

        print(f"\n{'=' * 80}")
        print(f"第 {gen} 代最优解信息:")
        print(f"总遮蔽时间: {total_occlusion:.2f}s")
        print(f"M1遮蔽时间: {missile_occlusion['M1']:.2f}s")
        print(f"M2遮蔽时间: {missile_occlusion['M2']:.2f}s")
        print(f"M3遮蔽时间: {missile_occlusion['M3']:.2f}s")
        print(f"惩罚值: {best_solution.penalty:.1f}")
        print(f"{'=' * 80}")

        # 打印Excel表格格式的信息
        print("\nExcel表格格式的无人机投放策略:")
        print("-" * 150)
        print(
            f"{'无人机编号':<8} | {'运动方向(°)':<12} | {'运动速度(m/s)':<12} | {'烟幕弹编号':<10} | {'投放时间(s)':<10} | {'引信延时(s)':<10} | "
            f"{'投放点x(m)':<12} | {'投放点y(m)':<12} | {'投放点z(m)':<12} | "
            f"{'起爆点x(m)':<12} | {'起爆点y(m)':<12} | {'起爆点z(m)':<12}")
        print("-" * 150)

        for strategy in strategies:
            smoke_windows = strategy.get_smoke_windows()

            for i, (_, _, explosion_point, release_point) in enumerate(smoke_windows):
                if i < 3:  # 只显示前3个烟幕弹
                    print(f"{strategy.drone_name:<8} | "
                          f"{math.degrees(strategy.alpha) % 360:>12.2f} | "
                          f"{strategy.v:>12.2f} | "
                          f"{i + 1:>10} | "
                          f"{strategy.release_times[i]:>10.2f} | "
                          f"{strategy.fuse_delays[i]:>10.2f} | "
                          f"{release_point[0]:>12.2f} | "
                          f"{release_point[1]:>12.2f} | "
                          f"{release_point[2]:>12.2f} | "
                          f"{explosion_point[0]:>12.2f} | "
                          f"{explosion_point[1]:>12.2f} | "
                          f"{explosion_point[2]:>12.2f}")

        print("-" * 150)
        print(f"{'有效干扰时长(s)':<12} | {total_occlusion:>10.2f}")
        print(f"{'干扰的观察者飞机编号':<12} | {'M1, M2, M3'}")
        print(f"{'=' * 80}\n")

    def select_best_solution_for_display(self, pareto_front: List[Solution]) -> Solution:
        """选择用于显示的最优解"""
        feasible_solutions = [s for s in pareto_front if s.penalty == 0]
        if not feasible_solutions:
            return min(pareto_front, key=lambda x: x.penalty)

        # 选择总遮蔽时间最长的解
        for solution in feasible_solutions:
            m1 = -solution.objectives[0]
            m2 = -solution.objectives[1]
            m3 = -solution.objectives[2]
            solution.total_occlusion = m1 + m2 + m3

        return max(feasible_solutions, key=lambda x: x.total_occlusion)


# ==================== Excel输出函数 ====================
def save_to_excel(strategies: List[DroneStrategy], total_occlusion: float,
                  missile_occlusion: Dict, filename: str = 'result3.xlsx'):
    """保存结果到Excel文件"""
    data = []

    for strategy in strategies:
        smoke_windows = strategy.get_smoke_windows()

        for i, (_, _, explosion_point, release_point) in enumerate(smoke_windows):
            if i < 3:
                data.append({
                    '无人机编号': strategy.drone_name,
                    '无人机运动方向(度)': round(math.degrees(strategy.alpha) % 360, 2),
                    '无人机运动速度(m/s)': round(strategy.v, 2),
                    '烟幕干扰弹编号': i + 1,
                    '投放时间(s)': round(strategy.release_times[i], 2),
                    '引信延时(s)': round(strategy.fuse_delays[i], 2),
                    '投放点x坐标(m)': round(release_point[0], 2),
                    '投放点y坐标(m)': round(release_point[1], 2),
                    '投放点z坐标(m)': round(release_point[2], 2),
                    '起爆点x坐标(m)': round(explosion_point[0], 2),
                    '起爆点y坐标(m)': round(explosion_point[1], 2),
                    '起爆点z坐标(m)': round(explosion_point[2], 2),
                    'M1遮蔽时间(s)': round(missile_occlusion['M1'], 2),
                    'M2遮蔽时间(s)': round(missile_occlusion['M2'], 2),
                    'M3遮蔽时间(s)': round(missile_occlusion['M3'], 2),
                    '总遮蔽时间(s)': round(total_occlusion, 2)
                })

    df = pd.DataFrame(data)
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='投放策略', index=False)
        worksheet = writer.sheets['投放策略']
        for col_idx, column in enumerate(df.columns, 1):
            max_length = max(df[column].astype(str).map(len).max(), len(column))
            worksheet.column_dimensions[chr(64 + col_idx)].width = min(max_length + 2, 50)

    print(f"结果已保存到 {filename}")


def select_final_solution(pareto_front: List[Solution]) -> Solution:
    """从Pareto前沿中选择最终解"""
    if not pareto_front:
        return Solution(np.zeros(40), (0, 0, 0), 0)

    feasible_solutions = [s for s in pareto_front if s.penalty == 0]
    if not feasible_solutions:
        feasible_solutions = sorted(pareto_front, key=lambda x: x.penalty)

    for solution in feasible_solutions:
        m1 = -solution.objectives[0]
        m2 = -solution.objectives[1]
        m3 = -solution.objectives[2]
        solution.total_occlusion = m1 + m2 + m3
        solution.min_occlusion = min(m1, m2, m3)
        solution.balance_score = 1.0 / (abs(m1 - m2) + abs(m2 - m3) + abs(m1 - m3) + 1e-6)
        solution.quality_score = (solution.total_occlusion +
                                  solution.min_occlusion * 2 +
                                  solution.balance_score * 5)

    return max(feasible_solutions, key=lambda x: x.quality_score)


# ==================== 主程序 ====================
def main():
    """主函数"""
    print("NSGA-II算法优化5架无人机协同干扰策略...")
    print("优化参数: 种群大小=150, 最大代数=300, 交叉率=0.9, 变异率=0.15")
    print("严格遮蔽条件：导弹到目标点的视线被烟幕球遮蔽")

    start_time = time.time()

    optimizer = NSGA2Optimizer(
        pop_size=150,
        max_gens=300,
        crossover_rate=0.9,
        mutation_rate=0.15,
        n_workers=14  # 使用14个核心
    )

    pareto_front = optimizer.optimize()
    final_solution = select_final_solution(pareto_front)
    best_strategies = optimizer.decode_chromosome(final_solution.chromosome)

    # 重新计算遮蔽时间（确保精度）
    missile_occlusion = calculate_occlusion_times(best_strategies)
    total_occlusion = sum(missile_occlusion.values())

    # 输出最终结果
    print("\n" + "=" * 80)
    print("优化完成！最终结果:")
    print(f"总计算时间: {time.time() - start_time:.1f}秒")
    print(f"总遮蔽时间: {total_occlusion:.2f}秒")
    print(f"导弹M1遮蔽时间: {missile_occlusion['M1']:.2f}秒")
    print(f"导弹M2遮蔽时间: {missile_occlusion['M2']:.2f}秒")
    print(f"导弹M3遮蔽时间: {missile_occlusion['M3']:.2f}秒")
    print(f"惩罚值: {final_solution.penalty:.1f}")
    print(f"Pareto最优解数量: {len(pareto_front)}")
    print("=" * 80)

    # 保存结果
    save_to_excel(best_strategies, total_occlusion, missile_occlusion, 'result3plus.xlsx')

    # 保存详细策略
    detailed_result = {
        'total_occlusion': total_occlusion,
        'missile_occlusion': missile_occlusion,
        'strategies': [],
        'pareto_front_size': len(pareto_front),
        'computation_time': time.time() - start_time,
        'cpu_cores_used': optimizer.n_workers
    }

    for strategy in best_strategies:
        detailed_result['strategies'].append({
            'drone': strategy.drone_name,
            'heading_deg': round(math.degrees(strategy.alpha) % 360, 2),
            'speed': round(strategy.v, 2),
            'release_times': [round(t, 2) for t in strategy.release_times],
            'fuse_delays': [round(t, 2) for t in strategy.fuse_delays]
        })

    with open('nsga3plus_optimized_results.json', 'w', encoding='utf-8') as f:
        json.dump(detailed_result, f, indent=2, ensure_ascii=False)

    print("详细结果已保存到 nsga3plus_optimized_results.json")

    return best_strategies, total_occlusion, missile_occlusion


if __name__ == "__main__":
    # Windows系统需要添加这行代码
    mp.freeze_support()
    strategies, total_time, missile_times = main()
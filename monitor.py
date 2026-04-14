#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
external_monitor.py - 外部监控NSGA-II优化进度（10分钟更新一次）
无需修改主程序，定期输出result3.xlsx需要的数据
"""
import json
import time
import numpy as np
import math
import pandas as pd
from datetime import datetime

# 常量定义（与主程序一致）
g = 9.8
DRONES = {
    'FY1': np.array([17800.0, 0.0, 1800.0]),
    'FY2': np.array([12000.0, 1400.0, 1400.0]),
    'FY3': np.array([6000.0, -3000.0, 700.0]),
    'FY4': np.array([11000.0, 2000.0, 1800.0]),
    'FY5': np.array([13000.0, -2000.0, 1300.0])
}


def load_current_best():
    """从JSON文件加载当前最优解"""
    try:
        with open('nsga2_optimized_results.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def calculate_positions(drone_name, alpha, v, release_times, fuse_delays):
    """计算投放点和起爆点坐标"""
    drone_pos = DRONES[drone_name]
    u = np.array([math.cos(alpha), math.sin(alpha), 0.0])

    positions = []
    for tr, tu in zip(release_times, fuse_delays):
        # 投放点
        release_point = drone_pos + v * tr * u
        release_point[2] = drone_pos[2]  # 保持高度

        # 起爆点
        explosion_point = (release_point +
                           v * tu * u +
                           np.array([0.0, 0.0, -0.5 * g * tu * tu]))

        positions.append({
            'release_point': release_point,
            'explosion_point': explosion_point
        })

    return positions


def generate_excel_data(optimization_data):
    """生成Excel所需的数据"""
    data = []

    for strategy in optimization_data['strategies']:
        # 转换角度为弧度
        alpha_rad = math.radians(strategy['heading_deg'])

        # 计算坐标
        positions = calculate_positions(
            strategy['drone'], alpha_rad, strategy['speed'],
            strategy['release_times'], strategy['fuse_delays']
        )

        for i, pos in enumerate(positions):
            data.append({
                '无人机编号': strategy['drone'],
                '无人机运动方向(度)': strategy['heading_deg'],
                '无人机运动速度(m/s)': strategy['speed'],
                '烟幕干扰弹编号': i + 1,
                '投放时间(s)': strategy['release_times'][i],
                '引信延时(s)': strategy['fuse_delays'][i],
                '投放点x坐标(m)': round(pos['release_point'][0], 2),
                '投放点y坐标(m)': round(pos['release_point'][1], 2),
                '投放点z坐标(m)': round(pos['release_point'][2], 2),
                '起爆点x坐标(m)': round(pos['explosion_point'][0], 2),
                '起爆点y坐标(m)': round(pos['explosion_point'][1], 2),
                '起爆点z坐标(m)': round(pos['explosion_point'][2], 2),
                'M1遮蔽时间(s)': round(optimization_data['missile_occlusion']['M1'], 2),
                'M2遮蔽时间(s)': round(optimization_data['missile_occlusion']['M2'], 2),
                'M3遮蔽时间(s)': round(optimization_data['missile_occlusion']['M3'], 2),
                '总遮蔽时间(s)': round(optimization_data['total_occlusion'], 2)
            })

    return data


def save_to_excel(data, filename):
    """保存数据到Excel"""
    df = pd.DataFrame(data)
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='投放策略', index=False)

        # 设置列宽
        worksheet = writer.sheets['投放策略']
        for col_idx, column in enumerate(df.columns, 1):
            max_length = max(df[column].astype(str).map(len).max(), len(column))
            worksheet.column_dimensions[chr(64 + col_idx)].width = min(max_length + 2, 20)

    print(f"Excel文件已保存: {filename}")


def monitor_optimization():
    """主监控函数 - 每10分钟更新一次"""
    print("🚀 NSGA-II优化进度监控器")
    print("📊 监控文件: nsga2_optimized_results.json")
    print("⏰ 更新频率: 每10分钟一次")
    print("=" * 50)

    last_update = None
    check_interval = 600  # 10分钟 = 600秒

    while True:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{current_time}] 检查优化进度...")

        current_data = load_current_best()

        if current_data:
            # 检查是否有更新
            if current_data != last_update:
                print("✅ 检测到新的优化结果!")
                print(f"📈 总遮蔽时间: {current_data['total_occlusion']:.2f}s")
                print(f"🎯 M1遮蔽: {current_data['missile_occlusion']['M1']:.2f}s")
                print(f"🎯 M2遮蔽: {current_data['missile_occlusion']['M2']:.2f}s")
                print(f"🎯 M3遮蔽: {current_data['missile_occlusion']['M3']:.2f}s")
                print(f"⏱️  计算时间: {current_data['computation_time']:.1f}s")
                print(f"📋 Pareto解数量: {current_data['pareto_front_size']}")

                # 生成Excel数据
                print("💾 生成Excel文件...")
                excel_data = generate_excel_data(current_data)

                # 保存Excel文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M")
                excel_filename = f"result3_{timestamp}.xlsx"
                save_to_excel(excel_data, excel_filename)

                # 同时保存一个最新的副本
                save_to_excel(excel_data, "result3_latest.xlsx")

                print("✅ 文件保存完成!")
                last_update = current_data
            else:
                print("ℹ️  结果文件无更新")
        else:
            print("⏳ 等待结果文件生成...")

        # 显示下次检查时间
        next_check = datetime.now().timestamp() + check_interval
        next_check_time = datetime.fromtimestamp(next_check).strftime("%H:%M:%S")
        print(f"⏰ 下次检查时间: {next_check_time}")
        print("=" * 50)

        # 10分钟等待
        time.sleep(check_interval)


if __name__ == "__main__":
    try:
        monitor_optimization()
    except KeyboardInterrupt:
        print("\n🛑 监控已停止")
    except Exception as e:
        print(f"❌ 监控出错: {e}")
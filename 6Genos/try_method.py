import pickle
import ipaddress
import itertools
import subprocess
import math
import time
import heapq
import random
from collections import defaultdict
import concurrent.futures
import re  
import gc
import psutil
import tracemalloc
import threading
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# External probe backend config
# =========================
PROBE_BACKEND_DIR = "/home/chenjing/GAP6/New-address-discovery"
PROBE_PROTOCOL = "ack_rst"   # 可改成别的协议
PROBE_TIMEOUT = 600
PROBE_VERBOSE = True

#open('./res_log_1.txt', 'w').close()
# 保留辅助函数
def get_memory_usage():
    """获取当前进程的内存使用情况（MB）"""
    process = psutil.Process()
    return process.memory_info().rss / (1024 * 1024)

def log_memory(tag, prev_memory=None):
    """记录当前内存使用和差值"""
    current_memory = get_memory_usage()
    memory_diff = current_memory - prev_memory if prev_memory is not None else 0
    print(f"[内存] {tag}: {current_memory:.2f} MB (变化: {memory_diff:+.2f} MB)")
    return current_memory

def log_time(tag, start_time):
    """记录运行时间"""
    elapsed = time.time() - start_time
    print(f"[时间] {tag}: {elapsed:.4f} 秒")
    return time.time()

# 在代码中保留NodeFamily类定义，用于反序列化pickle文件
class NodeFamily:
    def __init__(self, two_star=None, three_star=None, four_star=None, five_star=None, one_star=None):
        """
        创建一个节点家族，存储不同星级节点的引用
        """
        self.one_star = one_star      # 对1星节点的引用
        self.two_star = two_star      # 对2星节点的引用
        self.three_star = three_star  # 对3星节点的引用
        self.four_star = four_star    # 对4星节点的引用
        self.five_star = five_star    # 对5星节点的引用
        
        self.family_score = 0.0  # 家族整体得分
        self.active = True       # 家族是否活跃

class TreeNode:
    def __init__(self, pattern, star_level=0, parent=None, R=0.5):
        # 原有属性
        self.parent = parent
        self.pattern = pattern
        self.childs = []  # 子节点列表(星数更低)
        self.use = False  # 原代码中的使用标记
        self.SS = set()
        self.NDA = 0
        self.AAD = 0
        self.R = R  # 节点先验概率
        self.one = False
        self.two = False
        self.three = False
        self.four = False
        self.five = False
        self.starnum = 0
        
        # 新增属性
        self.init_R = R
        self.old_R = R
        self.brothers = []  #兄弟节点列表（星数一样）
        self.star_level = star_level  # 星级 (1,2,3,4,5)
        self.parents = []  # 父节点列表（星数更高）
        self.used = False  # 是否已确定命中率(新的标记系统)
        self.update_count = 0  # 在一轮更新中的更新次数
        
        # 条件概率 - 假设已在导入节点时设置
        self.conditional_probs = {}  # 格式: {node: probability}
        
        # 新增: 存储归属于该节点的活跃地址
        self.active_addresses = set()
        
        # 新增: 存储最近一轮为该节点生成的地址
        self.recent_generated_addresses = set()
    
    def set_conditional_probability(self, target_node, probability):
        """设置当前节点到目标节点的条件概率"""
        self.conditional_probs[target_node] = probability
    
    def get_conditional_probability(self, target_node):
        """获取当前节点到目标节点的条件概率，如不存在则返回默认值0.1"""
        return self.conditional_probs.get(target_node, 0.1)
    
    def add_child(self, child):
        """添加子节点，并建立双向连接"""
        if child not in self.childs:
            self.childs.append(child)
            if self not in child.parents:
                child.parents.append(self)
    
    def is_child(self, node):
        # 原有逻辑，判断是否为子节点模式
        three_star = self.pattern
        four_star = node.pattern
        if len(four_star) == len(three_star):
            diff_count = 0
            match = True
            for i in range(len(three_star)):
                if three_star[i] != four_star[i]:
                    if three_star[i].isdigit() and four_star[i] == '*':
                        diff_count += 1
                    else:
                        match = False
                        return False
            return match and diff_count == 1
        return False
    
    def __str__(self):
        return f"Node({self.star_level}★: {self.pattern}, R={self.R:.4f}, used={self.used}, active={len(self.active_addresses)})"

class RewardChangeQueue:
    """自定义优先队列，按奖励值变化大小排序，使用堆实现高效操作"""
    def __init__(self):
        self.queue = []  # 最小堆，用负值实现最大堆
        self.in_queue = set()  # 跟踪队列中的(node, source_node)对
        self.counter = 0  # 解决优先级相同时的顺序问题
    
    def push(self, delta_r, node, source_node):
        """添加更新操作到队列，以 -delta_r 为优先级（实现最大堆）"""
        # 避免重复添加相同的(node, source_node)对
        queue_key = (node, source_node)
        if queue_key in self.in_queue:
            return
        
        # 使用负值实现最大堆，counter 保证顺序稳定
        heapq.heappush(self.queue, (-delta_r, self.counter, node, source_node))
        self.in_queue.add(queue_key)
        self.counter += 1
    
    def pop(self):
        """弹出奖励值变化最大的操作"""
        if not self.queue:
            return None, None, None
        
        neg_delta_r, _, node, source_node = heapq.heappop(self.queue)
        self.in_queue.remove((node, source_node))
        return -neg_delta_r, node, source_node
    
    def is_empty(self):
        """检查队列是否为空"""
        return len(self.queue) == 0
    
    def clear(self):
        """清空队列释放内存"""
        self.queue = []
        self.in_queue = set()
        self.counter = 0

def select_top_nodes_with_heap(nodes, n, min_score=None):
    """
    使用小根堆优化选择分数最高的n个活跃节点
    
    参数:
        nodes: 所有节点列表 
        n: 要返回的节点数量
        min_score: 最小分数阈值，只选择分数大于等于此值的节点
    
    返回:
        前n个高分节点列表（按分数降序排列）
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    min_heap = []
    entry_counter = 0  # 用于处理相同分数的节点比较问题
    
    for node in nodes:
        # 跳过已使用的节点
        if node.used:
            continue
            
        # 检查分数阈值
        if min_score is not None and node.R < min_score:
            continue
        
        # 使用小根堆维护TopN
        entry = (node.R, entry_counter, node)
        entry_counter += 1
        
        if len(min_heap) < n:
            heapq.heappush(min_heap, entry)
        else:
            if node.R > min_heap[0][0]:
                heapq.heappop(min_heap)
                heapq.heappush(min_heap, entry)
    
    # 按分数降序排列结果（相同分数按插入顺序）
    result = [item[2] for item in sorted(min_heap, key=lambda x: (-x[0], x[1]))]
    
    log_time(f"select_top_nodes_with_heap(n={n})", start_time)
    log_memory(f"select_top_nodes_with_heap", initial_memory)
    print(f"使用优化版小根堆选择了 {len(result)}/{n} 个活跃节点")
    return result

def select_top_nodes_by_star_level(nodes, counts_by_star, min_scores=None):
    """
    按星级选择指定数量的节点，每个星级维护独立的小根堆
    
    参数:
        nodes: 所有节点列表
        counts_by_star: 每个星级要选择的节点数量 {star_level: count}
        min_scores: 可选的每个星级的最小分数阈值 {star_level: min_score}
        
    返回:
        所有星级选择的节点合并列表
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    # 为每个星级创建小根堆和计数器
    heaps = {}
    counters = {}
    processed_counts = defaultdict(int)
    valid_counts = defaultdict(int)
    
    # 初始化所有堆
    for star_level in counts_by_star:
        heaps[star_level] = []
        counters[star_level] = 0
    
    # 一次遍历所有节点
    for node in nodes:
        star_level = node.star_level
        
        # 如果这个星级不在配置中，跳过
        if star_level not in counts_by_star or counts_by_star[star_level] <= 0:
            continue
        
        # 计算该星级已处理节点数
        processed_counts[star_level] += 1
        
        # 跳过已使用的节点
        if node.used:
            continue
        
        # 检查最小分数阈值
        min_score = None if min_scores is None else min_scores.get(star_level)
        if min_score is not None and node.R < min_score:
            continue
        
        # 该星级有效节点数+1
        valid_counts[star_level] += 1
        
        # 获取当前星级的堆和计数器
        min_heap = heaps[star_level]
        counter = counters[star_level]
        
        # 使用小根堆维护TopN
        entry = (node.R, counter, node)
        counters[star_level] += 1
        
        if len(min_heap) < counts_by_star[star_level]:
            heapq.heappush(min_heap, entry)
        else:
            if node.R > min_heap[0][0]:
                heapq.heappop(min_heap)
                heapq.heappush(min_heap, entry)
    
    # 处理每个星级的结果
    results = []
    total_selected = 0
    
    # 打印星级分布和选择情况
    for star_level in sorted(heaps.keys()):
        # 按分数降序排列结果（相同分数按插入顺序）
        star_results = [item[2] for item in sorted(heaps[star_level], key=lambda x: (-x[0], x[1]))]
        
        # 添加到总结果
        results.extend(star_results)
        total_selected += len(star_results)
        
        print(f"星级 {star_level}: 总节点 {processed_counts[star_level]}个, "
              f"有效节点 {valid_counts[star_level]}个, "
              f"选出 {len(star_results)}/{counts_by_star[star_level]}个")
    
    log_time("select_top_nodes_by_star_level", start_time)
    log_memory("select_top_nodes_by_star_level", initial_memory)
    
    total_requested = sum(counts_by_star.values())
    print(f"按星级选择完成: 共选出 {total_selected}/{total_requested} 个节点")
    
    return results
# def select_top_nodes_approx_extreme(nodes, n, min_score=None, num_threads=None):
#     """
#     极致性能、多线程版的近似筛选节点：
#       1. 将节点列表分成多个chunk，每个线程处理一个chunk
#       2. 每个线程把节点分为两个列表：
#          - high_candidates：分数 >= (min_score+0.005)
#          - low_candidates：  min_score <= 分数 < (min_score+0.005)
#       3. 合并所有线程结果，然后：
#          - 若 high_candidates >= n，则结果直接取其前 n 个；
#          - 否则，先放入所有 high_candidates，然后再从 low_candidates 中取足 (n - len(high_candidates)) 个。

#     参数:
#         nodes       : 所有节点列表
#         n           : 需要返回的节点数量
#         min_score   : 最小分数阈值，若为 None，表示不启用阈值筛选
#         num_threads : 线程数量，默认为None（根据CPU核心数自动决定）

#     返回:
#         选出的节点列表（数量不超过 n），按扫描顺序排列
#     """
#     start_time = time.time()
#     initial_memory = get_memory_usage()
    
#     # 设置线程数量，默认为CPU核心数的2倍
#     if num_threads is None:
#         import multiprocessing
#         num_threads = multiprocessing.cpu_count() * 2
    
#     # 设置高阈值
#     high_threshold = min_score + 0.005 if min_score is not None else float('-inf')
    
#     # 计算每个线程处理的数据量
#     chunk_size = max(1, len(nodes) // num_threads)
#     chunks = [nodes[i:i+chunk_size] for i in range(0, len(nodes), chunk_size)]
    
#     # 用于存储每个线程的结果
#     results = {}
#     result_lock = threading.Lock()
    
#     # 定义处理chunk的函数
#     def process_chunk(chunk, min_score=None, high_threshold=None, results=None, chunk_id=None, lock=None):
#         """处理一个节点子列表，找出符合条件的high_candidates和low_candidates"""
#         high_candidates = []
#         low_candidates = []
        
#         for node in chunk:
#             # 跳过已使用的节点
#             if node.used:
#                 continue
                
#             # 获取节点分数
#             score = node.R
            
#             # 根据阈值分配
#             if score >= high_threshold:
#                 high_candidates.append(node)
#             elif score >= min_score:
#                 low_candidates.append(node)
        
#         # 使用锁安全地更新共享结果
#         with lock:
#             results[chunk_id] = (high_candidates, low_candidates)
            
#         return high_candidates, low_candidates
    
#     # 创建线程池
#     with ThreadPoolExecutor(max_workers=num_threads) as executor:
#         # 提交所有线程任务
#         futures = [
#             executor.submit(
#                 process_chunk, 
#                 chunk, 
#                 min_score, 
#                 high_threshold, 
#                 results, 
#                 i, 
#                 result_lock
#             ) for i, chunk in enumerate(chunks)
#         ]
        
#         # 等待所有线程完成
#         for future in as_completed(futures):
#             # 可以在这里处理线程异常
#             try:
#                 future.result()
#             except Exception as e:
#                 print(f"线程执行出错: {e}")
    
#     # 合并所有线程的结果
#     all_high_candidates = []
#     all_low_candidates = []
    
#     for _, (high, low) in sorted(results.items()):
#         all_high_candidates.extend(high)
#         all_low_candidates.extend(low)
    
#     # 如果已经在 high_candidates 中凑够 n 个，直接返回
#     if len(all_high_candidates) >= n:
#         result = all_high_candidates[:n]
#     else:
#         # high_candidates 不足 n，需要再从 low_candidates 里补
#         needed = n - len(all_high_candidates)
#         result = all_high_candidates + all_low_candidates[:needed]
    
#     log_time(f"select_top_nodes_approx_extreme_threaded(n={n}, threads={num_threads})", start_time)
#     log_memory("select_top_nodes_approx_extreme_threaded", initial_memory)
#     print(f"使用多线程({num_threads}线程)近似法选出了 {len(result)}/{n} 个节点")
#     return result

def standardize_ipv6_hex(addr, target_length=32):
    """
    标准化IPv6十六进制地址，确保长度一致为32个字符
    这是关键函数，所有地址处理必须经过这个函数确保格式一致
    """
    ip = ipaddress.IPv6Address(addr)
    exploded = ip.exploded.replace(':', '')
    return exploded

# 优化的地址转换函数
def convert(seeds):
    converted = []
    for ip_str in seeds:
        try:
            ip = ipaddress.IPv6Address(ip_str)
            exploded = ip.exploded.replace(':', '')
            converted.append(exploded)
        except:
            continue
    return converted

def convert_batched(seeds, batch_size=90000000):
    """批处理版本的convert，使用缓冲减少内存峰值，确保标准化格式"""
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    total_seeds = len(seeds)
    converted = []
    processed = 0
    
    # 多线程并行转换
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        # 分批处理
        futures = []
        for i in range(0, total_seeds, batch_size):
            end_idx = min(i + batch_size, total_seeds)
            batch = seeds[i:end_idx]
            futures.append(executor.submit(convert, batch))
        
        # 收集结果
        for future in concurrent.futures.as_completed(futures):
            try:
                batch_result = future.result()
                converted.extend(batch_result)
                processed += len(batch_result)
                
                # 报告进度
                if processed % 500000 == 0 or processed >= total_seeds - batch_size:
                    progress = processed / total_seeds * 100
                    print(f"[进度] 地址转换: {processed}/{total_seeds} ({progress:.1f}%)")
            except Exception as e:
                print(f"地址转换批次失败: {e}")
    
    log_time(f"convert_batched({total_seeds}个地址)", start_time)
    log_memory(f"convert_batched", initial_memory)
    
    return converted

# 简化的地址归属方法 - 使用标准化地址格式
def assign_addresses_direct(scanned_hex_addresses, nodes):
    """
    简化的地址归属 - 使用节点的recent_generated_addresses和集合操作
    确保所有地址使用相同的标准化格式
    
    参数:
        scanned_hex_addresses: 扫描到的活跃地址(十六进制格式)
        nodes: 要检查的节点列表
        
    返回:
        活跃节点集合
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    # 创建扫描到地址的集合，确保标准化格式
    scanned_set = set(scanned_hex_addresses)
    active_nodes = set()
    total_match_count = 0
    
    # 清除所有节点的活跃地址
    for node in nodes:
        node.active_addresses = set()
    
    # 直接处理所有节点（移除多线程和批次处理）
    for node in nodes:
        # 确保节点的recent_generated_addresses也是标准化格式
        standardized_generated = node.recent_generated_addresses
        # 计算交集
        matches = standardized_generated.intersection(set(scanned_set))
        if len(matches)!=0:
            # 记录活跃地址
            node.active_addresses = matches
            active_nodes.add(node)
            total_match_count += len(matches)
    
    print(f"直接归属: {total_match_count} 个活跃地址归属到 {len(active_nodes)} 个节点")
    
    log_time("assign_addresses_direct", start_time)
    log_memory("assign_addresses_direct", initial_memory)
    
    return active_nodes

# 基于生成记录计算命中率
def calculate_node_hit_rates(nodes):
    """
    基于节点的recent_generated_addresses和active_addresses计算命中率
    
    参数:
        nodes: 节点列表
        
    返回:
        命中率字典 {node: hit_rate}
    """
    start_time = time.time()
    
    hit_rates = {}
    
    # 定义处理批次的函数
    def process_batch(node_batch):
        batch_hit_rates = {}
        
        for node in node_batch:
            # 确保节点的地址集合是标准化格式
            standardized_generated = set(addr for addr in node.recent_generated_addresses)
            standardized_active = set(addr for addr in node.active_addresses)
            
            # 生成的地址总数
            generated_count = len(standardized_generated)
            
            # 命中的地址数
            hit_count = len(standardized_active)
            
            # 计算命中率
            if generated_count > 0:
                hit_rate = hit_count / generated_count
                batch_hit_rates[node] = hit_rate
        
        return batch_hit_rates
    
    # 将节点分批处理
    batch_size = max(1, len(nodes) // 8)  # 根据核心数调整批次大小
    node_batches = [list(nodes)[i:i+batch_size] for i in range(0, len(nodes), batch_size)]
    
    # 使用线程池并行处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(process_batch, batch) for batch in node_batches]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                batch_hit_rates = future.result()
                hit_rates.update(batch_hit_rates)
            except Exception as e:
                print(f"命中率计算批次处理失败: {e}")
    
    log_time("calculate_node_hit_rates", start_time)
    
    return hit_rates

class NodeRewardSystem:
    def __init__(self):
        """初始化节点奖励系统"""
        # 为每个星级维护单独的节点集合
        self.nodes_by_star = {
            1: set(),
            2: set(),
            3: set(),
            4: set(),
            5: set()
        }
        # 缓存BGP前缀相关数据
        self.bgp_prefix_info = {
            'prefix_len': None,     # BGP前缀长度(位)
            'hex_len': None,        # BGP前缀16进制字符数
            'skip_positions': None  # 需要跳过的前缀位置
        }
    
    def register_node(self, node):
        """注册节点到系统中"""
        if node.star_level in self.nodes_by_star:
            self.nodes_by_star[node.star_level].add(node)
    
    def register_nodes_from_list(self, nodes_list, star_level):
        """从列表中批量注册节点"""
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        for node in nodes_list:
            node.star_level = star_level  # 确保星级正确设置
            self.register_node(node)
        
        log_time(f"register_nodes_from_list({star_level}★)", start_time)
        log_memory(f"register_nodes_from_list({star_level}★)", initial_memory)
    
    def reset_update_counts(self):
        """重置所有节点的更新计数"""
        for star_level in self.nodes_by_star:
            for node in self.nodes_by_star[star_level]:
                node.update_count = 0

    def set_bgp_prefix_info(self, bgp_prefix_len=None):
        """设置BGP前缀相关信息"""
        if bgp_prefix_len is None:
            bgp_prefix_len = 40  # 默认40位
        
        # 计算前缀十六进制长度
        hex_len = math.ceil(bgp_prefix_len / 4)
        
        # 计算需要跳过的前缀位置
        skip_positions = max(0, hex_len - 8) if hex_len > 8 else 0
        
        # 存储信息
        self.bgp_prefix_info = {
            'prefix_len': bgp_prefix_len,
            'hex_len': hex_len,
            'skip_positions': skip_positions
        }
        
        print(f"设置BGP前缀信息: {bgp_prefix_len}位 ({hex_len}个16进制字符), 跳过前缀位置: {skip_positions}")
        return self.bgp_prefix_info

    # def batch_update_node_rewards(self, nodes_with_hits, hit_rates, threshold=0.01):
    #     """
    #     基于归属的活跃地址批量更新节点奖励
        
    #     参数:
    #         nodes_with_hits: 有命中的节点集合
    #         hit_rates: 节点命中率字典 {node: hit_rate}
    #         threshold: 更新阈值
        
    #     返回:
    #         所有被更新的节点集合
    #     """
    #     start_time = time.time()
    #     initial_memory = get_memory_usage()
        
    #     all_updated_nodes = set()
        
    #     # 1. 直接更新有命中的节点
    #     direct_updated_nodes = set()
        
    #     for node in nodes_with_hits:
    #         hit_rate = hit_rates.get(node, 0)
    #         if hit_rate > 0:
    #             old_r = node.R
    #             node.R = hit_rate
    #             node.used = True
    #             node.use = True
    #             direct_updated_nodes.add(node)
    #             all_updated_nodes.add(node)
        
    #     print(f"直接更新了 {len(direct_updated_nodes)} 个有命中的节点")
        
    #     # 2. 多星到少星的传播
    #     high_to_low_updates = self._perform_high_to_low_propagation(direct_updated_nodes, hit_rates, threshold)
    #     all_updated_nodes.update(high_to_low_updates)
        
    #     # 3. 同星级更新 - 使用多线程优化
    #     seed_nodes = direct_updated_nodes.union(high_to_low_updates)
    #     print(f"同星级更新开始，种子节点数量: {len(seed_nodes)}")
    #     same_level_updates = self._batch_update_same_level_parallel(seed_nodes, threshold)
    #     all_updated_nodes.update(same_level_updates)
        
    #     # 4. 少星到多星的更新 - 使用多线程优化
    #     all_updated_so_far = seed_nodes.union(same_level_updates)
    #     low_to_high_updates = self._batch_update_low_to_high_parallel(all_updated_so_far)
    #     all_updated_nodes.update(low_to_high_updates)
        
    #     # 同步old_R
    #     for node in all_updated_nodes:
    #         node.old_R = node.R
        
    #     print(f"批量更新完成：共更新了 {len(all_updated_nodes)} 个节点")
    #     return all_updated_nodes
    def check_address_matches_pattern(self, address, pattern):
        """
        检查地址是否匹配给定的模式
        
        参数:
            address: 标准化的32字符十六进制地址
            pattern: 节点的模式字符串
            
        返回:
            布尔值，表示是否匹配
        """
        # 获取BGP前缀信息
        bgp_info = self.bgp_prefix_info
        hex_length = bgp_info.get('hex_len', 8)
        
        # 需要从地址中提取BGP前缀部分
        if hex_length > 8:
            # 从地址中获取BGP前缀
            bgp_prefix = address[:hex_length]
            full_pattern = bgp_prefix + pattern[hex_length-8:]
        else:
            # BGP前缀没有超过8位，从地址中获取前缀
            bgp_prefix = address[:hex_length]
            full_pattern = bgp_prefix + pattern
        
        # 确保模式长度为32个字符
        full_pattern = full_pattern.ljust(32, '0')[:32]
        
        # 检查地址是否匹配模式（*可以是任意字符）
        if len(address) != len(full_pattern):
            return False
        
        for addr_char, pattern_char in zip(address, full_pattern):
            if pattern_char != '*' and addr_char != pattern_char:
                return False
        
        return True

    def _update_brother_nodes_parallel(self, nodes_with_hits, max_workers=32):
        """
        并行更新兄弟节点的活跃地址和命中率
        
        参数:
            nodes_with_hits: 有命中的节点集合
            max_workers: 最大线程数
            
        返回:
            更新的兄弟节点集合
        """
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        print(f"开始并行更新兄弟节点，使用 {max_workers} 个线程..")
        
        # 按星级分组
        nodes_by_star = defaultdict(list)
        for node in nodes_with_hits:
            if len(node.active_addresses) > 0 and len(node.brothers) > 0:
                nodes_by_star[node.star_level].append(node)
        
        all_updated_brothers = set()
        update_lock = threading.Lock()
        
        def process_star_level(star_level, nodes):
            """处理特定星级的兄弟节点更新"""
            local_updated_brothers = set()
            processed_count = 0
            
            for node in nodes:
                # 预先收集该节点的活跃地址
                node_active_addresses = list(node.active_addresses)
                
                # 遍历该节点的所有兄弟节点
                for brother in node.brothers:
                    # 只更新未使用过的兄弟节点，跳过已有命中的兄弟节点
                    if brother.used or brother in nodes_with_hits:
                        continue
                    
                    # 检查当前节点的活跃地址是否符合兄弟节点的地址范围
                    matching_addresses = set()
                    
                    # 使用高效的模式匹配
                    for address in node_active_addresses:
                        if self.check_address_matches_pattern(address, brother.pattern):
                            matching_addresses.add(address)
                    
                    # 如果有匹配的地址，更新兄弟节点
                    if matching_addresses:
                        # 将匹配的地址加入兄弟节点的活跃地址（去重）
                        original_count = len(brother.active_addresses)
                        brother.active_addresses.update(matching_addresses)
                        new_count = len(brother.active_addresses)
                        
                        if new_count > original_count:  # 确实有新地址加入
                            # 重新计算命中率，但保持未使用状态
                            generated_count = len(brother.recent_generated_addresses)
                            if generated_count > 0:
                                hit_rate = new_count / generated_count
                                brother.R = hit_rate
                                # 注意：不设置 brother.used = True，保持未使用状态
                                # brother.used 保持 False
                                # brother.use 保持 False
                                local_updated_brothers.add(brother)
                
                processed_count += 1
                
                # 每处理100个节点打印一次进度
                if processed_count % 100 == 0:
                    print(f"  {star_level}★ 已处理 {processed_count}/{len(nodes)} 个节点")
            
            return local_updated_brothers
        
        # 使用线程池并行处理各星级
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有星级的任务
            future_to_star = {}
            for star_level, nodes in nodes_by_star.items():
                future = executor.submit(process_star_level, star_level, nodes)
                future_to_star[future] = star_level
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_star):
                star_level = future_to_star[future]
                try:
                    star_updated_brothers = future.result()
                    with update_lock:
                        all_updated_brothers.update(star_updated_brothers)
                    print(f"  {star_level}★ 更新了 {len(star_updated_brothers)} 个兄弟节点")
                except Exception as exc:
                    print(f"处理 {star_level} 星级兄弟节点时出错: {exc}")
        
        log_time("_update_brother_nodes_parallel", start_time)
        log_memory("_update_brother_nodes_parallel", initial_memory)
        
        print(f"兄弟节点更新完成: 共更新了 {len(all_updated_brothers)} 个兄弟节点（保持未使用状态）")
        return all_updated_brothers

    def batch_update_node_rewards(self, nodes_with_hits, hit_rates, threshold=0.01):
        """
        基于归属的活跃地址批量更新节点奖励（已更新版本）
        
        参数:
            nodes_with_hits: 有命中的节点集合
            hit_rates: 节点命中率字典 {node: hit_rate}
            threshold: 更新阈值
        
        返回:
            所有被更新的节点集合
        """
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        all_updated_nodes = set()
        
        # 1. 直接更新有命中的节点
        direct_updated_nodes = set()
        
        for node in nodes_with_hits:
            hit_rate = hit_rates.get(node, 0)
            if hit_rate > 0:
                old_r = node.R
                node.R = hit_rate
                node.used = True
                node.use = True
                direct_updated_nodes.add(node)
                all_updated_nodes.add(node)
        
        print(f"直接更新了 {len(direct_updated_nodes)} 个有命中的节点")
        
        # 2. 新增：更新兄弟节点（在多星到少星传播之前）
        print("开始更新兄弟节点..")
        brother_updated_nodes = self._update_brother_nodes_parallel(direct_updated_nodes)
        all_updated_nodes.update(brother_updated_nodes)
        
        # 将兄弟节点更新结果合并到命中率字典中
        for brother in brother_updated_nodes:
            generated_count = len(brother.recent_generated_addresses)
            active_count = len(brother.active_addresses)
            if generated_count > 0:
                hit_rates[brother] = active_count / generated_count
        
        print(f"兄弟节点更新了 {len(brother_updated_nodes)} 个节点")
        
        # 3. 多星到少星的传播
        # 现在包括直接更新的节点和兄弟节点更新的节点
        seed_nodes = direct_updated_nodes.union(brother_updated_nodes)
        high_to_low_updates = self._perform_high_to_low_propagation(seed_nodes, hit_rates, threshold)
        all_updated_nodes.update(high_to_low_updates)
        
        # 4. 同星级更新 - 使用多线程优化
        all_seed_nodes = seed_nodes.union(high_to_low_updates)
        print(f"同星级更新开始，种子节点数量: {len(all_seed_nodes)}")
        same_level_updates = self._batch_update_same_level_parallel(all_seed_nodes, threshold)
        all_updated_nodes.update(same_level_updates)
        
        # 5. 少星到多星的更新 - 使用多线程优化
        all_updated_so_far = all_seed_nodes.union(same_level_updates)
        low_to_high_updates = self._batch_update_low_to_high_parallel(all_updated_so_far)
        all_updated_nodes.update(low_to_high_updates)
        
        # 同步old_R
        for node in all_updated_nodes:
            node.old_R = node.R
        
        print(f"批量更新完成：共更新了 {len(all_updated_nodes)} 个节点")
        print(f"  - 直接更新: {len(direct_updated_nodes)} 个")
        print(f"  - 兄弟节点更新: {len(brother_updated_nodes)} 个") 
        print(f"  - 多星到少星: {len(high_to_low_updates)} 个")
        print(f"  - 同星级更新: {len(same_level_updates)} 个")
        print(f"  - 少星到多星: {len(low_to_high_updates)} 个")
        
        log_time("batch_update_node_rewards", start_time)
        log_memory("batch_update_node_rewards", initial_memory)
        
        return all_updated_nodes

    def _batch_update_same_level_parallel(self, update_nodes, threshold=0.01, max_workers=128):
        """批量处理同星级更新，使用多线程并行处理各星级"""
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        # 按星级分组
        nodes_by_star_level = defaultdict(list)
        for node in update_nodes:
            if node.used:  # 只处理used节点
                nodes_by_star_level[node.star_level].append(node)
        
        # 定义星级更新函数
        def update_star_level(star_level, nodes):
            level_start_time = time.time()
            level_updated_nodes = set()
            
            # 创建优先队列
            update_queue = RewardChangeQueue()
            
            # 预计算delta_r值
            delta_r_cache = {}
            push_count = 0
            
            # 加入所有初始更新操作
            for source_node in nodes:
                delta_r = source_node.R - source_node.old_R
                delta_r_cache[source_node] = delta_r
                
                # 跳过变化很小的节点
                if abs(delta_r) < threshold:
                    continue
                
                # 传播到源节点的兄弟节点
                for target_node in source_node.brothers:
                    if target_node is not source_node and not target_node.used:
                        cond_prob = source_node.get_conditional_probability(target_node)
                        propagated_delta = delta_r * cond_prob
                        
                        if abs(propagated_delta) >= threshold:
                            update_queue.push(abs(propagated_delta), target_node, source_node)
                            push_count += 1
            
            # 记录每个节点的累积更新信息
            node_updates = {}  # {node: (total_change, update_count)}
            
            # 记录已处理过的节点，避免重复传播
            processed_nodes = set()
            
            # 按优先级处理队列
            process_count = 0
            
            while not update_queue.is_empty():
                _, target_node, source_node = update_queue.pop()
                process_count += 1
                
                # 打印进度
                if process_count % 100000 == 0:
                    print(f"  {star_level}星级: 已处理 {process_count} 个队列项")
                
                # 获取缓存的delta_r
                delta_r = delta_r_cache.get(source_node, 0)
                
                # 获取条件概率
                cond_prob = source_node.get_conditional_probability(target_node)
                
                # 计算传播的变化量
                propagated_delta = delta_r * cond_prob
                
                # 更新目标节点的累积变化
                if target_node not in node_updates:
                    node_updates[target_node] = (0, 0)  # (total_change, count)
                
                total_change, count = node_updates[target_node]
                total_change += propagated_delta
                count += 1
                node_updates[target_node] = (total_change, count)
                
                # 标记为已处理
                processed_nodes.add(target_node)
                
                # 只从目标节点继续传播到它的兄弟节点，形成链式传播
                for next_node in target_node.brothers:
                    # 避免传播回源节点或已处理的节点
                    if (next_node is not source_node and
                        next_node is not target_node and
                        next_node not in processed_nodes and
                        not next_node.used):
                        
                        next_cond_prob = target_node.get_conditional_probability(next_node)
                        next_delta = propagated_delta * next_cond_prob
                        
                        if abs(next_delta) >= threshold:
                            update_queue.push(abs(next_delta), next_node, target_node)
            
            # 应用累积变化到每个节点
            update_count = 0
            
            for target_node, (total_change, count) in node_updates.items():
                # 计算平均变化量
                avg_change = total_change / count if count > 0 else 0
                
                # 更新节点奖励值
                target_node.R += avg_change
                
                # 确保R值在合理范围内
                if target_node.R > 1.0:
                    target_node.R = 1.0
                elif target_node.R < 0.0:
                    target_node.R = 0.0
                
                # 添加到更新节点集合
                level_updated_nodes.add(target_node)
                update_count += 1
            
            # 清理级别更新的内存
            delta_r_cache = None
            processed_nodes = None
            update_queue.clear()
            node_updates = None
            
            return level_updated_nodes
        
        # 使用线程池并行处理各星级
        all_updated_nodes = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有星级的任务
            future_to_star = {}
            for star_level, nodes in nodes_by_star_level.items():
                future = executor.submit(update_star_level, star_level, nodes)
                future_to_star[future] = star_level
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_star):
                star_level = future_to_star[future]
                try:
                    star_updated_nodes = future.result()
                    all_updated_nodes.update(star_updated_nodes)
                except Exception as exc:
                    print(f"处理 {star_level} 星级节点时出错: {exc}")
        
        # 性能监控 - 函数整体结束
        log_time("_batch_update_same_level_parallel - 总计", start_time)
        log_memory("_batch_update_same_level_parallel - 总计", initial_memory)
        
        return all_updated_nodes

    def _batch_update_low_to_high_parallel(self, update_nodes, max_workers=32):
        """多线程并行处理低星到高星的更新"""
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        all_updated_nodes = set()
        
        # 按星级分组
        nodes_by_star = defaultdict(set)
        for node in update_nodes:
            if node.used:  # 只处理used节点
                nodes_by_star[node.star_level].add(node)
        
        # 定义处理一个星级的函数
        def process_star_level(star_level, nodes):
            level_start = time.time()
            level_updated_nodes = set()
            
            # 收集所有待更新的父节点及其增量
            parent_updates = defaultdict(float)
            
            # 处理每个低星节点
            for low_node in nodes:
                increment = low_node.R / 1.1
                
                # 找出所有星级更高的父节点并累计增量
                for parent in low_node.parents:
                    if parent.star_level > star_level and not parent.used:
                        parent_updates[parent] += increment
            
            # 批量应用所有父节点更新
            update_count = 0
            for parent, total_increment in parent_updates.items():
                parent.R += total_increment
                
                # 确保R值不超过1
                if parent.R > 1.0:
                    parent.R = 1.0
                
                level_updated_nodes.add(parent)
                update_count += 1
            
            return level_updated_nodes
        
        # 按星级从低到高，使用多线程并行处理
        star_levels_sorted = sorted(nodes_by_star.keys())
        
        # 使用线程池并行处理
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有星级的任务
            future_to_star = {}
            for star_level in star_levels_sorted:
                future = executor.submit(process_star_level, star_level, nodes_by_star[star_level])
                future_to_star[future] = star_level
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_star):
                star_level = future_to_star[future]
                try:
                    star_updated_nodes = future.result()
                    all_updated_nodes.update(star_updated_nodes)
                except Exception as exc:
                    print(f"处理 {star_level} 星级节点时出错: {exc}")
        
        # 性能监控 - 结束
        log_time("_batch_update_low_to_high_parallel", start_time)
        log_memory("_batch_update_low_to_high_parallel", initial_memory)
        
        return all_updated_nodes

    def _perform_high_to_low_propagation(self, updated_nodes, hit_rates, threshold=0.01):
        """
        基于节点的活跃地址进行多星到少星传播
        
        参数:
            updated_nodes: 已更新的节点集合
            hit_rates: 节点命中率字典 {node: hit_rate}
            threshold: 命中率阈值
            
        返回:
            更新的节点集合
        """
        # 性能监控
        start_time = time.time()
        initial_memory = get_memory_usage()
        
        # 按星级分组高星节点
        nodes_by_star = defaultdict(list)
        for node in updated_nodes:
            if node.used and node.R > 0:
                nodes_by_star[node.star_level].append((node, hit_rates.get(node, 0)))
        
        high_to_low_updates = set()
        
        # 定义处理一个星级的函数
        def process_star_level(star_level, level_nodes):
            level_updates = set()
            
            # 按命中率排序，优先处理高价值节点
            level_nodes.sort(key=lambda x: x[1], reverse=True)
            
            # 根据父节点的活跃地址更新子节点
            for parent, parent_hit_rate in level_nodes:
                # 如果父节点没有活跃地址，跳过
                if len(parent.active_addresses) == 0:
                    continue
                
                # 处理所有子节点
                for child in parent.childs:
                    # 只处理星级更低且未使用的子节点
                    if child.star_level < star_level and not child.used:
                        # 计算星级差异
                        star_diff = star_level - child.star_level
                        
                        # 根据星级差异调整传播系数
                        propagation_factor = 0.9 ** star_diff
                        
                        # 计算子节点的命中率
                        child_hit_rate = parent_hit_rate * propagation_factor
                        
                        # 如果命中率高于阈值，更新子节点
                        if child_hit_rate >= threshold:
                            # 更新活跃地址集合 - 将父节点的活跃地址传递给子节点
                            child.active_addresses.update(parent.active_addresses)
                            
                            # 设置子节点的奖励值
                            child.R = child_hit_rate
                            child.used = True
                            child.use = True
                            
                            # 添加到已更新节点集合
                            level_updates.add(child)
            
            return level_updates
        
        # 使用多线程并行处理不同星级 - 从高星到低星
        star_levels_sorted = sorted(nodes_by_star.keys(), reverse=True)
        
        # 多线程处理各星级
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            # 提交所有星级的任务
            future_to_star = {}
            for star_level in star_levels_sorted:
                future = executor.submit(process_star_level, star_level, nodes_by_star[star_level])
                future_to_star[future] = star_level
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_star):
                star_level = future_to_star[future]
                try:
                    level_updates = future.result()
                    high_to_low_updates.update(level_updates)
                except Exception as exc:
                    print(f"处理 {star_level} 星级节点时出错: {exc}")
        
        # 清理内存
        nodes_by_star = None
        
        # 性能监控
        log_time("_perform_high_to_low_propagation", start_time)
        log_memory("_perform_high_to_low_propagation", initial_memory)
        
        return high_to_low_updates

def read_graph(file_path):
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    try:
        print(f"正在加载图结构: {file_path}")
        with open(file_path, 'rb') as file:
            graph = pickle.load(file)
        print("数据加载成功，开始处理..")

        one_star_nodes = graph.get('one_star_nodes', [])
        two_star_nodes = graph.get('two_star_nodes', [])
        three_star_nodes = graph.get('three_star_nodes', [])
        four_star_nodes = graph.get('four_star_nodes', [])
        five_star_nodes = graph.get('five_star_nodes', [])
        families = graph.get('families', [])  # 仍然读取但不使用

        print(f"初始数据: {len(one_star_nodes)} 个1星节点, {len(two_star_nodes)} 个2星节点, "
              f"{len(three_star_nodes)} 个3星节点, {len(four_star_nodes)} 个4星节点, "
              f"{len(five_star_nodes)} 个5星节点")

        load_time = log_time("read_graph - 加载数据", start_time)
        load_memory = log_memory("read_graph - 加载数据", initial_memory)

        # 将字符串模式转换回节点对象
        all_nodes = one_star_nodes + two_star_nodes + three_star_nodes + four_star_nodes + five_star_nodes
        node_dict = {node.pattern: node for node in all_nodes}
        print(f"创建节点字典，共 {len(node_dict)} 个唯一节点")

        dict_time = log_time("read_graph - 创建节点字典", load_time)
        dict_memory = log_memory("read_graph - 创建节点字典", load_memory)

        # 恢复节点之间的引用
        for i, nodes_list in enumerate([one_star_nodes, two_star_nodes, three_star_nodes, four_star_nodes, five_star_nodes]):
            star_level = i + 1
            print(f"处理 {star_level} 星节点..")
            
            for node in nodes_list:
                # 恢复子节点引用
                if isinstance(node.childs, list) and node.childs and isinstance(node.childs[0], str):
                    node.childs = [node_dict[pattern] for pattern in node.childs if pattern in node_dict]
                
                # 恢复父节点引用
                if hasattr(node, 'parents') and isinstance(node.parents, list) and node.parents and isinstance(node.parents[0], str):
                    node.parents = [node_dict[pattern] for pattern in node.parents if pattern in node_dict]
                
                # 恢复兄弟节点引用
                if hasattr(node, 'brothers') and isinstance(node.brothers, list) and node.brothers and isinstance(node.brothers[0], str):
                    node.brothers = [node_dict[pattern] for pattern in node.brothers if pattern in node_dict]
                
                # 恢复条件概率字典中的节点引用
                if hasattr(node, 'conditional_probs') and node.conditional_probs:
                    new_probs = {}
                    for pattern, prob in node.conditional_probs.items():
                        if pattern in node_dict:
                            new_probs[node_dict[pattern]] = prob
                    node.conditional_probs = new_probs
                
                # 确保节点具有所有必要属性
                if not hasattr(node, 'used'):
                    node.used = False
                if not hasattr(node, 'old_R'):
                    node.old_R = node.R
                if not hasattr(node, 'init_R'):
                    node.init_R = node.R  
                if not hasattr(node, 'update_count'):
                    node.update_count = 0
                if not hasattr(node, 'conditional_probs'):
                    node.conditional_probs = {}
                if not hasattr(node, 'active_addresses'):
                    node.active_addresses = set()
                if not hasattr(node, 'recent_generated_addresses'):
                    node.recent_generated_addresses = set()
                    
                # 设置星级属性
                node.star_level = star_level

        nodes_time = log_time("read_graph - 节点引用恢复完成", dict_time)
        nodes_memory = log_memory("read_graph - 节点引用恢复完成", dict_memory)

        # 清理不再需要的数据
        node_dict = None
        gc.collect()
        
        log_time("read_graph - 完成", start_time)
        log_memory("read_graph - 完成", initial_memory)

        # 返回节点列表，最后一个返回None表示不再使用家族
        return one_star_nodes, two_star_nodes, three_star_nodes, four_star_nodes, five_star_nodes
        
    except FileNotFoundError:
        print("未找到保存的图结构文件，请确保文件存在。")
        return None, None, None, None, None, None
    except Exception as e:
        print(f"读取图结构时出现错误: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None, None, None

def sort_three_star_nodes_by_R(three_star_nodes):
    if three_star_nodes:
        sorted_nodes = sorted(three_star_nodes, key=lambda node: node.R, reverse=True)
    return sorted_nodes


def pre_scan(bgps, pattern_node, num, random_ratio=0.5):
    """
    为给定的模式生成地址，确保格式一致性
    
    参数:
        bgps: BGP前缀，格式如"2605:59c7:f003::/48"
        pattern_node: 模式节点对象
        num: 要生成的地址数量
        random_ratio: 随机生成的比例，范围[0,1]之间的浮点数
    
    返回:
        生成的地址迭代器
    """
    # 提取BGP前缀信息
    bgp, length = bgps.split('/')
    length = int(length)
    
    # 计算16进制位数
    hex_length = math.ceil(length / 4)
    hex_length = max(8, hex_length)
    
    # 确保bgp是标准化的十六进制格式
    try:
        bgp_ip = ipaddress.IPv6Address(bgp)
        bgp_hex = bgp_ip.exploded.replace(':', '')
    except:
        # 如果转换失败，使用原来的转换方法
        bgp_hex = convert([bgp])[0]
    
    # 获取BGP前缀部分
    bgp_prefix = bgp_hex[:hex_length]
    
    # 构建完整模式 - 处理BGP前缀
    if hex_length > 8:
        # 模式前(hex_length-8)位需要用BGP前缀替换
        full_pattern = bgp_prefix + pattern_node.pattern[hex_length-8:]
    else:
        # BGP前缀没有超过8位，直接使用
        full_pattern = bgp_prefix + pattern_node.pattern
    
    # 确保模式长度为32个字符
    full_pattern = full_pattern.ljust(32, '0')[:32]
    
    parts = full_pattern.split('*')
    star_count = len(parts) - 1

    # 如果没有星号，直接返回完整模式
    if star_count == 0:
        yield full_pattern
        return

    # 计算可能的组合总数
    possible_comb_count = 16 ** star_count
    
    # 实际要生成的数量不能超过可能的组合总数
    actual_num = min(num, possible_comb_count)
    
    # 计算随机生成和顺序生成的数量
    random_count = int(actual_num * random_ratio)
    sequential_count = actual_num - random_count
    
    hex_chars = '0123456789abcdef'
    
    # 顺序生成部分 - 针对不同星级优化
    if sequential_count > 0:
        if star_count == 1:  # 1星模式优化
            prefix = parts[0]
            suffix = parts[1]
            for i in range(min(16, sequential_count)):
                yield (prefix + hex_chars[i] + suffix)
        
        elif star_count == 2:  # 2星模式优化
            prefix = parts[0]
            middle = parts[1]
            suffix = parts[2]
            count = 0
            for i in range(16):
                for j in range(16):
                    if count >= sequential_count:
                        break
                    yield (prefix + hex_chars[i] + middle + hex_chars[j] + suffix)
                    count += 1
                if count >= sequential_count:
                    break
        
        else:  # 3星及以上通用处理
            count = 0
            for indices in itertools.product(range(16), repeat=star_count):
                if count >= sequential_count:
                    break
                
                # 使用列表构建然后一次性join，避免多次字符串拼接
                result = [parts[0]]
                for i, index in enumerate(indices):
                    result.append(hex_chars[index])
                    result.append(parts[i + 1])
                
                yield ''.join(result)
                count += 1
    
    # 随机生成部分
    for _ in range(random_count):
        # 随机选择每个*位置的值
        hex_values = [random.choice(hex_chars) for _ in range(star_count)]
        
        # 使用列表构建并一次join
        result = [parts[0]]
        for i in range(star_count):
            result.append(hex_values[i])
            result.append(parts[i + 1])
        
        yield ''.join(result)

def parallel_efficient_pre_scan(bgps, nodes, counts_per_star, random_ratio=0.5, max_total=500000, max_workers=32):
    """
    多线程并行生成预探测地址，无批处理
    
    参数:
        bgps: BGP前缀
        nodes: 要生成地址的节点列表 [(node, star_level), ..]
        counts_per_star: 每个星级生成的地址数 {star_level: count, ..}
        random_ratio: 随机生成比例
        max_total: 最大总地址数
        max_workers: 最大线程数
        
    返回:
        生成的(standardized_addr, node)列表
    """
    start_time = time.time()
    
    # 按星级分组
    nodes_by_star = defaultdict(list)
    for node, star_level in nodes:
        nodes_by_star[star_level].append((node, star_level))
    
    all_results = []
    total_generated = 0
    
    # 清空所有节点的recent_generated_addresses
    for star_level in nodes_by_star:
        for node, _ in nodes_by_star[star_level]:
            node.recent_generated_addresses = set()
            node.use=False
            node.used=False
    
    # 创建一个生成任务的函数
    def generate_for_node(node, star_level, count):
        result = []
        
        # 确定随机生成和顺序生成的比例
        random_count = int(count * random_ratio)
        sequential_count = count - random_count
        
        # 根据星级使用不同的生成策略
        for std_addr in pre_scan(bgps, node, count, random_ratio):
            # 标准化地址 - 使用统一的函数保证格式一致
            
            result.append((std_addr, node))
            
            # 记录到节点
            node.recent_generated_addresses.add(std_addr)
        
        return result
    
    # 对每个星级分别处理
    for star_level, star_nodes in nodes_by_star.items():
        count_per_node = counts_per_star.get(star_level, 0)
        if count_per_node == 0:
            continue
        
        #print(f"为{len(star_nodes)}个{star_level}星节点生成预探测地址，每个节点{count_per_node}个")
        
        # 限制每个星级的节点数，以控制总地址数
        if len(star_nodes) * count_per_node > max_total:
            node_limit = max(1, max_total // count_per_node)
            print(f"  限制处理节点数为{node_limit}，以控制总地址数")
            star_nodes = random.sample(star_nodes, min(node_limit, len(star_nodes)))
        
        # 创建任务列表
        tasks = []
        for node, _ in star_nodes:
            tasks.append((node, star_level, count_per_node))
        
        # 使用线程池并行执行任务
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_task = {}
            for task in tasks:
                node, star_level, count = task
                future = executor.submit(generate_for_node, node, star_level, count)
                future_to_task[future] = (node, star_level)
            
            # 收集结果
            completed = 0
            
            for future in concurrent.futures.as_completed(future_to_task):
                node, star_level = future_to_task[future]
                try:
                    node_results = future.result()
                    all_results.extend(node_results)
                    total_generated += len(node_results)
                    
                    # 如果地址已超限，提前退出
                    if total_generated >= max_total:
                        break
                
                except Exception as exc:
                    print(f"节点 {node.pattern} 生成地址失败: {exc}")
                
                completed += 1
                # 打印进度
                if completed % max(1, len(tasks) // 10) == 0:
                    progress = completed / len(tasks) * 100
                    #print(f"[进度] {star_level}★ 预探测地址生成: {completed}/{len(tasks)} 个节点 ({progress:.1f}%)")
        
        print(f"  {star_level}★ 星级共生成 {total_generated} 个预探测地址")
        
        # 检查是否达到总数限制
        if total_generated >= max_total:
            print(f"已达到最大地址数限制({max_total})，停止生成")
            break
    
    print(f"预探测地址生成完成，总共生成 {total_generated} 个地址")
    print(f"预探测地址生成耗时: {time.time() - start_time:.2f} 秒")
    
    return all_results

def generate_combinations(bgp, node, max_count=None):
    """
    生成给定节点的全部地址组合
    
    参数:
        bgp: BGP前缀
        node: 要生成组合的节点
        max_count: 最大生成数量，默认为None表示生成全部
    """
    # 从BGP提取网络前缀
    network, prefix_len = bgp.split('/')
    prefix_len = int(prefix_len)
    
    # 计算16进制长度
    hex_length = math.ceil(prefix_len / 4)
    hex_length = max(8, hex_length)
    
    # 转换BGP前缀为16进制
    try:
        bgp_ip = ipaddress.IPv6Address(network)
        bgp_hex = bgp_ip.exploded.replace(':', '')
    except:
        bgp_hex = convert([network])[0]
    
    # 获取BGP前缀部分
    bgp_prefix = bgp_hex[:hex_length]
    
    # 构建完整模式
    if hex_length > 8:
        # 模式前(hex_length-8)位需要用BGP前缀替换
        full_pattern = bgp_prefix + node.pattern[hex_length-8:]
    else:
        # BGP前缀没有超过8位，直接使用
        full_pattern = bgp_prefix + node.pattern
    
    # 确保模式长度为32个字符
    full_pattern = full_pattern.ljust(32, '0')[:32]
    
    # 分解模式
    parts = full_pattern.split('*')
    star_count = len(parts) - 1
    
    # 如果没有星号，直接返回完整模式
    if star_count == 0:
        yield full_pattern
        return
    
    # 计算总组合数
    total_combinations = 16 ** star_count
    
    # 如果指定了最大数量且小于总组合数，随机选择部分组合
    hex_chars = '0123456789abcdef'
    
    if max_count is not None and max_count < total_combinations:
        # 随机生成组合
        generated = set()
        attempts = 0
        max_attempts = max_count * 2  # 设置最大尝试次数，避免死循环
        
        while len(generated) < max_count and attempts < max_attempts:
            # 随机选择每个*位置的值
            values = [random.choice(hex_chars) for _ in range(star_count)]
            
            # 构建完整地址
            combined = parts[0]
            for i in range(star_count):
                combined += values[i] + parts[i + 1]
            
            if combined not in generated:
                generated.add(combined)
                yield combined
            
            attempts += 1
    else:
        # 生成所有可能的组合
        for repl in itertools.product(hex_chars, repeat=star_count):
            combined = parts[0]
            for i in range(star_count):
                combined += repl[i] + parts[i + 1]
            # 标准化为32字符长度
            combined = combined.ljust(32, '0')[:32]
            yield combined

def str2ipv6(compact):
    """确保正确转换为标准IPv6格式"""
    # 确保地址是32个字符长度
    if len(compact) != 32:
        compact = standardize_ipv6_hex(compact, 32)
    
    # 分成8组，每组4个字符
    return ':'.join([compact[i*4:(i+1)*4] for i in range(8)])

def run_probe_backend(bgp):
    start_time = time.time()

    input_file = './res0.txt'
    output_dir = './res0'
    output_file = f'{output_dir}/{bgp}.txt'

    try:
        # 1. 检查 6Genos 生成的候选地址文件是否存在
        if not os.path.exists(input_file):
            print(f"探测输入文件不存在: {input_file}")
            return False

        # 2. 确保输出目录存在
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # 3. 删除旧结果，避免混淆
        if os.path.exists(output_file):
            os.remove(output_file)

        # 4. 调用你的统一探测后端
        sudo_password = os.environ.get("SUDO_PASSWORD")
        command = [
            'sudo', '-S', '-p', '', './run.sh',
            PROBE_PROTOCOL,
            os.path.abspath(input_file),
            os.path.abspath(output_file)
        ]

        result = subprocess.run(
            command,
            cwd=PROBE_BACKEND_DIR,
            capture_output=True,
            text=True,
            input=f"{sudo_password}\n" if sudo_password else None,
            timeout=PROBE_TIMEOUT
        )

        if PROBE_VERBOSE:
            print(f"[probe_backend] protocol={PROBE_PROTOCOL}, bgp={bgp}")
            if result.stdout:
                print("[probe_backend stdout]")
                print(result.stdout)
            if result.stderr:
                print("[probe_backend stderr]")
                print(result.stderr)

        if result.returncode != 0:
            print(f"probe backend 执行失败，返回码: {result.returncode}")
            return False

        if not os.path.exists(output_file):
            print(f"探测输出文件未生成: {output_file}")
            return False

        if sudo_password:
            chown_result = subprocess.run(
                [
                    'sudo', '-S', '-p', '',
                    'chown',
                    f'{os.getuid()}:{os.getgid()}',
                    os.path.abspath(output_file),
                ],
                capture_output=True,
                text=True,
                input=f"{sudo_password}\n",
                timeout=30
            )
            if chown_result.returncode != 0:
                print(f"探测输出文件权限修正失败: {chown_result.stderr}")
                return False

        return True

    except subprocess.TimeoutExpired:
        print(f"probe backend 执行超时: protocol={PROBE_PROTOCOL}, bgp={bgp}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"probe backend 执行错误: {e}")
        return False
    except Exception as e:
        print(f"运行 probe backend 时出现未知错误: {e}")
        return False
    finally:
        log_time(f"run_probe_backend({bgp})", start_time)

def scan_addresses(bgp, addresses, all_scanned):
    """优化的地址扫描函数，使用缓冲写入减少I/O"""
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    bgp1 = bgp.replace('/', '_')
    # 优化集合运算
    addresses_set = set(addresses)
    filtered_addresses = list(addresses_set - all_scanned)
    
    print(f"过滤后待扫描: {len(filtered_addresses)}/{len(addresses)} 个地址")
    
    if not filtered_addresses:
        return [], 0
    
    # 使用缓冲写入文件
    with open('./res0.txt', 'w') as f:
        buffer = []
        for ip in filtered_addresses:
            try:
                # 验证IP格式
                buffer.append(f"{ip}\n")
            except:
                continue
                
        # 写入剩余的缓冲内容
        if buffer:
            f.writelines(buffer)
    
    # 执行扫描
    scan_count = len(filtered_addresses)
    ok = run_probe_backend(bgp1)

    if not ok:
        print(f"探测失败: {bgp1}")
    
    # 读取结果：smap 可能带表头，New-address-discovery 不带表头。
    # 这里只接受合法 IPv6 地址，避免误跳过第一条真实命中。
    result_file = f'./res0/{bgp1}.txt'
    scanned_ips = []
    
    try:
        with open(result_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if not ip:
                    continue
                try:
                    ipaddress.IPv6Address(ip)
                except ValueError:
                    continue
                scanned_ips.append(ip)
    except FileNotFoundError:
        print(f"警告: 扫描结果文件 {result_file} 不存在")
    except Exception as e:
        print(f"读取扫描结果时出错: {e}")
    
    log_time("scan_addresses", start_time)
    log_memory("scan_addresses", initial_memory)
    
    return scanned_ips, scan_count

def generate_addresses_for_node(bgp, node):
    """为单个节点生成所有可能的地址组合，并记录到节点的recent_generated_addresses"""
    start_time = time.time()
    
    results = []
    
    # 先清空节点的recent_generated_addresses
    node.recent_generated_addresses = set()
    
    for combo in generate_combinations(bgp, node):
        # 标准化地址格式
        std_combo = standardize_ipv6_hex(combo, 32)
        results.append((std_combo, node))
        
        # 记录到节点
        node.recent_generated_addresses.add(std_combo)
    
    log_time(f"generate_addresses_for_node({node.pattern})", start_time)
    
    return results

def parallel_generate_addresses_full_scan(bgp, nodes, max_workers=32):
    """
    多线程并行为多个节点生成全探地址，无批处理
    
    参数:
        bgp: BGP前缀
        nodes: 包含(node, hit_rate)元组的列表，表示要生成地址的节点及其命中率
        max_workers: 最大线程数
        
    返回:
        生成的(standardized_addr, node)列表
    """



    start_time = time.time()
    print(f"开始多线程生成全探地址，使用 {max_workers} 个线程..")
    all_results=[]
    def generate_for_node(node, hit_rate):
        try:
            # 清空recent_generated_addresses
            node.recent_generated_addresses = set()
            
            # 记录生成结果
            result = []
            
            # 获取星号数量
            star_count = node.pattern.count('*')
            
            # 根据星号数量和命中率确定生成策略
            if star_count <= 6:
                # 1星或2星节点，生成所有可能组合

                for std_combo in generate_combinations(bgp, node):
                    # 确保使用统一的标准化函数
                    #std_combo = standardize_ipv6_hex(combo, 32)
                    result.append((std_combo, node))
                    # 记录到节点

                    node.recent_generated_addresses.add(std_combo)
                    node.use = True
                    node.used = True
            else:
                # 3星及以上，根据命中率调整生成数量
                # 命中率越高，生成越多
                base_count = 1000  # 基础数量
                count = min(10000, int(base_count * (1 + 10 * hit_rate)))
                
                for std_combo in generate_combinations(bgp, node, count):
                    # 确保使用统一的标准化函数
                    #std_combo = standardize_ipv6_hex(combo, 32)
                    
                    result.append((std_combo, node))
                    
                    # 记录到节点
                    node.recent_generated_addresses.add(std_combo)
            return result
        except Exception as e:
            print(f"节点 {node.pattern} 生成地址失败: {e}")
            return []
    
    # 使用线程池并行处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_node = {}
        for node, hit_rate in nodes:
            future = executor.submit(generate_for_node, node, hit_rate)
            future_to_node[future] = node
        
        # 收集结果
        total_combos = 0
        completed = 0
        total_nodes = len(nodes)
        
        for future in concurrent.futures.as_completed(future_to_node):
            node = future_to_node[future]
            try:
                combos = future.result()
                total_combos += len(combos)
                all_results.extend(combos)
            except Exception as exc:
                print(f"处理节点 {node.pattern} 结果时出错: {exc}")
            
            completed += 1
            # 打印进度
            if completed % max(1, total_nodes // 10) == 0 or completed == total_nodes:
                progress = completed / total_nodes * 100
                #print(f"[进度] 全探地址生成: {completed}/{total_nodes} 个节点 ({progress:.1f}%)")
    
    print(f"多线程生成完成，总共生成 {total_combos} 个组合")
    print(f"全探地址生成耗时: {time.time() - start_time:.2f} 秒")
    
    return all_results

def initial_probe_all_nodes(bgp, all_nodes):
    """
    针对每个节点只生成前4个地址的优化实现
    确保所有地址使用相同的标准化格式
    
    参数:
        bgp: BGP前缀
        all_nodes: 所有节点列表
        
    返回:
        命中的节点集合, 活跃IP列表, 探测数量
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    print(f"\n开始对BGP {bgp}的所有节点进行初始探测..")
    
    # 提取BGP前缀长度
    try:
        bgp_prefix_len = int(bgp.split('/')[1])
        print(f"BGP前缀长度: {bgp_prefix_len}位")
    except:
        bgp_prefix_len = 40  # 默认值
        print(f"无法解析BGP前缀长度，使用默认值: {bgp_prefix_len}位")
    
    # 从BGP提取网络前缀
    network, prefix_len = bgp.split('/')
    prefix_len = int(prefix_len)
    
    # 计算16进制长度
    hex_length = math.ceil(prefix_len / 4)
    hex_length = max(8, hex_length)
    
    # 转换BGP前缀为16进制
    try:
        bgp_ip = ipaddress.IPv6Address(network)
        bgp_hex = bgp_ip.exploded.replace(':', '')
    except:
        bgp_hex = convert([network])[0]
    
    # 获取BGP前缀部分
    bgp_prefix = bgp_hex[:hex_length]
    
    # 多线程生成地址
    all_generated = []
    lock = threading.Lock()
    
    # 每个线程处理的节点数量
    batch_size = 2000  # 可以根据系统性能调整
  
    # 为节点批次生成地址的线程函数
    def generate_batch_addresses(nodes_batch):
        batch_results = []
        hex_chars = '0123456789abcdef'
        
        for node in nodes_batch:
            try:
                # 清空recent_generated_addresses
                node.recent_generated_addresses = set()
                
                # 构建完整模式
                if hex_length > 8:
                    # 模式前(hex_length-8)位需要用BGP前缀替换
                    full_pattern = bgp_prefix
                    # 如果节点模式比需要的短，添加足够的0
                    if len(node.pattern) > (hex_length - 8):
                        full_pattern += node.pattern[(hex_length - 8):]
                    else:
                        # 节点模式太短，补充0
                        full_pattern += node.pattern.ljust(8, '0')[(hex_length - 8):]
                else:
                    # BGP前缀没有超过8位，直接使用
                    full_pattern = bgp_prefix + node.pattern[hex_length:]
                
                # 确保模式长度为32个字符
                full_pattern = full_pattern.ljust(32, '0')[:32]
                
                # 分解模式
                parts = full_pattern.split('*')
                star_count = len(parts) - 1
                
                # 如果没有星号，直接返回完整模式
                if star_count == 0:
                    addr = full_pattern
                    batch_results.append((addr, node))
                    node.recent_generated_addresses.add(addr)
                    continue
                
                # 统一策略：对所有节点只生成前4个地址
                addresses = []
                count = 0
                
                # 使用一个简单的生成器来产生替换组合
                def generate_replacements(star_count, hex_chars):
                    # 先生成按顺序的前几个组合
                    for combo in itertools.product(hex_chars[:4], repeat=star_count):
                        yield combo
                        
                # 获取前4个组合
                for repl in generate_replacements(star_count, hex_chars):
                    if count >= 4:
                        break
                    
                    combined = parts[0]
                    for i in range(star_count):
                        combined += repl[i] + parts[i + 1]
                    
                    # 标准化为32字符长度
                    addr = combined.ljust(32, '0')[:32]
                    addresses.append(addr)
                    count += 1
                
                # 将生成的地址添加到结果和节点记录中
                for addr in addresses:
                    batch_results.append((addr, node))
                    node.recent_generated_addresses.add(addr)
                
            except Exception as e:
                print(f"处理节点 {node.pattern if hasattr(node, 'pattern') else 'unknown'} 时出错: {e}")
                continue
        
        return batch_results
    
    batch_size = len(all_nodes) // 32 +1
    # 将节点分成多个批次
    node_batches = [all_nodes[i:i+batch_size] for i in range(0, len(all_nodes), batch_size)]
    
    # 使用线程池并行处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(generate_batch_addresses, batch) for batch in node_batches]
        
        # 收集结果
        for future in concurrent.futures.as_completed(futures):
            try:
                batch_results = future.result()
                with lock:
                    all_generated.extend(batch_results)
            except Exception as e:
                print(f"生成地址批次时出错: {str(e)}")
    
    print(f"为节点共生成 {len(all_generated)} 个初始探测地址")
    
    # 检查生成的地址 - 输出前10个作为样本
    
    # 如果没有生成任何地址，提前返回
    if not all_generated:
        print("没有生成任何地址，跳过扫描阶段")
        log_time("initial_probe_all_nodes - 完成(无地址生成)", start_time)
        log_memory("initial_probe_all_nodes - 完成", initial_memory)
        return set(), [], 0
    
    gen_time = log_time("initial_probe_all_nodes - 地址生成完成", start_time)
    
    # # 转换为标准IPv6格式
    # convert_start = time.time()
    # all_ips_to_scan = [str2ipv6(addr) for addr, _ in all_generated]
    # print(all_ips_to_scan[:10])
    # log_time("initial_probe_all_nodes - 地址格式转换", convert_start)

    if len(all_generated) != 0:
        print(f"预探共生成 {len(all_generated)} 个组合")
                        
        # 转换为IPv6格式 - 先提取所有地址再并行处理
        convert_start = time.time()
                        
        # 提取所有地址
        addr_list = [addr for addr, _ in all_generated]
        all_ips_to_scan = []  
                     
        # 批量转换函数 - 现在只处理地址字符串，不处理元组
        def convert_batch(addrs):
            result = []
            for addr in addrs:
                # 高效地构建IPv6地址字符串
                if len(addr) != 32:
                    addr = addr.ljust(32, '0')[:32]
                                
                # 使用内联分片构建IPv6地址
                ipv6 = f"{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}:{addr[20:24]}:{addr[24:28]}:{addr[28:32]}"
                result.append(ipv6)
            return result
                        
        # 并行处理地址
        batch_size = max(1, len(addr_list) // (32 * 2))
        batch_size = min(batch_size, 100000)
                        
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            futures = []
            for start_idx in range(0, len(addr_list), batch_size):
                end_idx = min(start_idx + batch_size, len(addr_list))
                futures.append(executor.submit(convert_batch, addr_list[start_idx:end_idx]))
                            
            for future in concurrent.futures.as_completed(futures):
                try:
                    batch_result = future.result()
                    all_ips_to_scan.extend(batch_result)
                except Exception as e:
                    print(f"转换地址出错: {e}")
                        
        log_time("预探地址转换", convert_start)

    
    # 扫描
    print(f"扫描 {len(all_ips_to_scan)} 个初始IP地址..")
    scanned_ips, scanned_count = scan_addresses(bgp, all_ips_to_scan, set())
    
    scan_time = log_time("initial_probe_all_nodes - 扫描完成", gen_time)
    
    # 释放不再需要的内存
    all_ips_to_scan = None
    
    # 如果有活跃地址，处理归属和命中率
    hit_nodes = set()
    if scanned_ips:
        print(f"初始探测发现 {len(scanned_ips)} 个活跃IP")
        
        # 转换扫描到的地址为标准十六进制格式
        process_start = time.time()
        scanned_hex_set = set(convert(scanned_ips))
        # 将活跃地址归属到节点 - 提取需要检查的节点列表
        nodes_to_check = []
        seen_nodes = set()
        for _, node in all_generated:
            if isinstance(node, TreeNode) and node not in seen_nodes:
                nodes_to_check.append(node)
                seen_nodes.add(node)
        
        print(f"准备将活跃地址归属给 {len(nodes_to_check)} 个唯一节点")
        
        # 使用直接归属方法
        assigned_nodes = assign_addresses_direct(scanned_hex_set, nodes_to_check)
        
        # 计算命中率
        hit_rates = calculate_node_hit_rates(assigned_nodes)
        
        # 设置命中率
        for node in assigned_nodes:
            hit_rate = hit_rates.get(node, 0)
            if hit_rate > 0:
                node.R = 0.0012
                node.used = False
                node.use = False
                hit_nodes.add(node)
        
        log_time("initial_probe_all_nodes - 命中率处理", process_start)
        
        # 清理内存
        scanned_hex_set = None
        nodes_to_check = None
        seen_nodes = None
    else:
        print("初始探测未发现活跃IP")
    
    # 清理内存
    all_generated = None
    
    log_time("initial_probe_all_nodes - 完成", start_time)
    log_memory("initial_probe_all_nodes - 完成", initial_memory)
    
    print(f"初始探测完成，共有 {len(hit_nodes)} 个节点有命中")
    return hit_nodes, scanned_ips, scanned_count

def reset_all_nodes_reward(all_nodes):
    """将所有节点的命中率重置为0，清空活跃地址列表和最近生成的地址列表"""
    start_time = time.time()
    
    # 多线程并行重置节点
    def reset_node_batch(node_batch):
        reset_count = 0
        for node in node_batch:
            if (node.R != node.init_R or node.used or node.use or 
                len(node.active_addresses) > 0 or len(node.recent_generated_addresses) > 0):
                node.R = node.init_R
                node.old_R = node.init_R
                node.used = False
                node.use = False
                node.active_addresses = set()  # 清空活跃地址列表
                node.recent_generated_addresses = set()  # 清空最近生成的地址列表
                reset_count += 1
        return reset_count
    
    # 分批处理
    total_reset = 0
    batch_size = 90000000
    node_batches = [all_nodes[i:i+batch_size] for i in range(0, len(all_nodes), batch_size)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(reset_node_batch, batch) for batch in node_batches]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                batch_reset = future.result()
                total_reset += batch_reset
            except Exception as e:
                print(f"重置节点批次出错: {e}")
    
    log_time("reset_all_nodes_reward", start_time)
    
    print(f"并行重置完成: 已将 {total_reset} 个节点的命中率重置为0，并清空活跃地址和生成地址列表")

def memory_cleanup_for_new_bgp():
    """BGP切换时的强化内存清理"""
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    #print("执行BGP切换时的内存清理..")
    
    # 执行多轮垃圾回收
    for _ in range(5):  # 增加回收次数
        gc.collect()
    
    # 主动触发额外内存回收
    import os
    if hasattr(os, 'sync'):  # Linux系统
        try:
            os.sync()  # 将文件系统缓冲区刷新到磁盘
        except:
            pass
    
    # 记录内存变化
    final_memory = get_memory_usage()
    memory_change = initial_memory - final_memory
    
    log_time("memory_cleanup_for_new_bgp", start_time)
    log_memory("memory_cleanup_for_new_bgp", initial_memory)
    
    #print(f"BGP间内存清理完成: 净减少 {memory_change:.2f} MB")
    
    return memory_change

def cleanup_bgp_memory(all_nodes, round_data=None):
    """
    BGP结束时进行彻底的内存清理
    
    参数:
        all_nodes: 所有节点列表
        round_data: 本轮探测中使用的临时数据
    
    返回:
        清理的内存大小(MB)
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    #print("\n===== 执行完整的BGP内存清理 =====")
    
    # 1. 清空所有节点的地址集合
    address_count = 0
    for node in all_nodes:
        address_count += len(node.recent_generated_addresses) + len(node.active_addresses)
        node.recent_generated_addresses.clear()  # 使用clear()方法更高效
        node.active_addresses.clear()
    
    #print(f"已清空 {address_count} 个地址引用")
    
    # 2. 显式删除临时数据
    if round_data is not None:
        for key, value in list(round_data.items()):
            if value is not None and isinstance(value, (list, set, dict)):
                if hasattr(value, 'clear'):
                    value.clear()
                round_data[key] = None
        
        #print(f"已清理 {len(round_data)} 个临时数据引用")
    
    # 3. 执行多轮垃圾回收
    collected = 0
    # 只对有效的三代(0,1,2)执行回收
    for i in range(3):  
        collected += gc.collect(i)
    
    # 额外进行一次全面回收
    collected += gc.collect()
    
    #print(f"垃圾回收器回收了 {collected} 个对象")
    
    # 4. 尝试释放未使用的内存回操作系统
    try:
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        if hasattr(libc, 'malloc_trim'):
            # 在Linux上，尝试使用malloc_trim释放内存
            libc.malloc_trim(0)
            #print("已执行malloc_trim释放内存")
    except:
        pass
    
    final_memory = get_memory_usage()
    freed_memory = initial_memory - final_memory
    
    #print(f"内存清理完成: 释放了 {freed_memory:.2f} MB 内存")
    #print("=====================================")
    
    log_time("cleanup_bgp_memory", start_time)
    return freed_memory

def monitor_memory_usage(tag):
    """定期监控内存使用"""
    current = get_memory_usage()
    #print(f"[内存监控] {tag}: 当前内存使用 {current:.2f} MB")
    
    if current > 8000:  # 超过8GB触发额外清理
        #print("[内存监控] 检测到内存使用过高，执行紧急清理")
        gc.collect(2)  # 强制对最老一代对象执行完整收集
        after_collect = get_memory_usage()
        #print(f"[内存监控] 紧急清理后内存: {after_collect:.2f} MB (减少: {current-after_collect:.2f} MB)")
    
    return current

def deduplicate_nodes_for_bgp_parallel(bgp, all_nodes, max_workers=32):
    """
    并行高性能版：为指定BGP对所有节点去重，将同一BGP下具有相同完整模式的节点标记为used
    
    参数:
        bgp: 当前处理的BGP前缀
        all_nodes: 所有节点列表
        max_workers: 最大线程数
        
    返回:
        保留的非重复节点数量
    """
    start_time = time.time()
    initial_memory = get_memory_usage()
    
    # 从BGP提取网络前缀信息
    network, prefix_len = bgp.split('/')
    prefix_len = int(prefix_len)
    
    # 计算16进制长度
    hex_length = math.ceil(prefix_len / 4)
    hex_length = max(8, hex_length)
    
    # 转换BGP前缀为16进制
    try:
        bgp_ip = ipaddress.IPv6Address(network)
        bgp_hex = bgp_ip.exploded.replace(':', '')
    except:
        bgp_hex = convert([network])[0]
    
    # 获取BGP前缀部分
    bgp_prefix = bgp_hex[:hex_length]
    
    # 计算有效节点数量（未标记为used的节点）
    active_nodes = [node for node in all_nodes if not node.used]
    active_count = len(active_nodes)
    
    if active_count == 0:
        #print("没有可去重的节点，全部已标记为used")
        return 0
    
    #print(f"开始对 {active_count} 个非used节点执行并行去重..")
    
    # 计算每个线程处理的节点数量
    batch_size = max(1, len(active_nodes) // max_workers)
    batches = [active_nodes[i:i+batch_size] for i in range(0, len(active_nodes), batch_size)]
    actual_workers = min(max_workers, len(batches))
    
    #print(f"划分为 {len(batches)} 个批次，使用 {actual_workers} 个线程")
    
    # 共享数据结构和锁
    thread_results = []  # 存储每个线程的结果
    results_lock = threading.Lock()
    stats_by_star = defaultdict(lambda: {"total": 0, "duplicates": 0})
    stats_lock = threading.Lock()
    
    def process_batch(batch, batch_id):
        """处理一个节点批次"""
        # 局部变量存储批次结果
        local_best_nodes = {}  # {full_pattern: (node, score)}
        local_marked_nodes = set()  # 需要标记为used的节点
        local_stats = defaultdict(lambda: {"total": 0, "duplicates": 0})
        
        # 处理批次中的每个节点
        for node in batch:
            # 构建完整模式
            if hex_length > 8:
                full_pattern = bgp_prefix + node.pattern[hex_length-8:]
            else:
                full_pattern = bgp_prefix + node.pattern
            
            # 确保模式长度为32个字符
            full_pattern = full_pattern.ljust(32, '0')[:32]
            
            # 更新统计信息
            local_stats[node.star_level]["total"] += 1
            
            # 检查是否已存在相同模式的节点
            if full_pattern in local_best_nodes:
                existing_node, existing_score = local_best_nodes[full_pattern]
                
                # 如果当前节点分数更高，则替换
                if node.R > existing_score:
                    local_best_nodes[full_pattern] = (node, node.R)
                    local_marked_nodes.add(existing_node)
                    local_stats[existing_node.star_level]["duplicates"] += 1
                else:
                    # 当前节点分数不更高，标记为used
                    local_marked_nodes.add(node)
                    local_stats[node.star_level]["duplicates"] += 1
            else:
                # 没有相同模式，添加到字典
                local_best_nodes[full_pattern] = (node, node.R)
        
        # 使用锁安全地更新共享结果
        with results_lock:
            thread_results.append((local_best_nodes, local_marked_nodes))
        
        # 更新总体统计信息
        with stats_lock:
            for star_level, counts in local_stats.items():
                stats_by_star[star_level]["total"] += counts["total"]
                stats_by_star[star_level]["duplicates"] += counts["duplicates"]
        
        return len(local_best_nodes), len(local_marked_nodes)
    
    # 使用线程池并行处理批次
    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
        # 提交所有批次任务
        futures = []
        for i, batch in enumerate(batches):
            futures.append(executor.submit(process_batch, batch, i))
        
        # 等待所有任务完成并收集结果
        for future in concurrent.futures.as_completed(futures):
            try:
                unique_count, marked_count = future.result()
            except Exception as e:
                print(f"处理批次时出错: {e}")
    
    # 合并所有线程的结果，处理冲突
    merged_best_nodes = {}  # {full_pattern: (node, score)}
    all_marked_nodes = set()
    
    # 合并线程结果处理
    for local_best_nodes, local_marked_nodes in thread_results:
        # 首先添加需要标记的节点
        all_marked_nodes.update(local_marked_nodes)
        
        # 处理每个线程找到的最佳节点，解决冲突
        for full_pattern, (node, score) in local_best_nodes.items():
            if full_pattern in merged_best_nodes:
                # 解决冲突：保留分数较高的节点
                existing_node, existing_score = merged_best_nodes[full_pattern]
                
                if score > existing_score:
                    # 新节点分数更高，替换并标记旧节点
                    merged_best_nodes[full_pattern] = (node, score)
                    all_marked_nodes.add(existing_node)
                else:
                    # 保留旧节点，标记新节点
                    all_marked_nodes.add(node)
            else:
                # 无冲突，直接添加
                merged_best_nodes[full_pattern] = (node, score)
    
    # 标记所有需要标记为used的节点
    marked_count = 0
    for node in all_marked_nodes:
        if not node.used:  # 避免重复标记
            node.used = True
            node.use = True  # 同时更新旧标记
            marked_count += 1
    
    # 计算保留的非重复节点数量
    kept_nodes = len(merged_best_nodes)
    
    # 打印统计信息
    #print(f"\nBGP {bgp} 节点并行去重结果:")
    #print(f"  总共处理 {active_count} 个非used节点")
    #print(f"  发现 {kept_nodes} 个唯一模式，标记 {marked_count} 个重复节点")
    
    for star_level in sorted(stats_by_star.keys()):
        stats = stats_by_star[star_level]
        total = stats["total"]
        duplicates = stats["duplicates"]
        kept = total - duplicates
        duplicate_rate = duplicates / total * 100 if total > 0 else 0
        
        #print(f"  {star_level}★: 总数 {total}, 去重 {duplicates}, 保留 {kept} (重复率: {duplicate_rate:.1f}%)")
    
    # 性能监控
    log_time("deduplicate_nodes_for_bgp_parallel", start_time)
    log_memory("deduplicate_nodes_for_bgp_parallel", initial_memory)
    
    return kept_nodes

def main():
    # 启用内存跟踪
    tracemalloc.start()
    
    # 记录程序开始的内存和时间
    program_start_time = time.time()
    program_start_memory = get_memory_usage()
    print(f"[程序开始] 初始内存使用: {program_start_memory:.2f} MB")
    
    buget_per_bgp0=300000
    buget_per_bgp=buget_per_bgp0*5
    epoch_1_percent=0.5
    # 参数设置
    TOP_NODES_COUNT = 500       # 每轮选择的顶级节点数量
    MAX_ROUNDS_PER_BGP = 4         # 每个BGP的最大探测轮数
    FULL_SCAN_THRESHOLD = 0.045     # 预探测命中率高于此值时进行全探
    MAX_FULL_SCAN_NODES = 20      # 每轮最多全探的节点数
    RANDOM_RATIO = 0.8              # 随机生成地址的比例，0-1之间的浮点数
    REWARD_SYSTEM_THRESHOLD = 0.3   # 条件概率更新的阈值 - 降低以增加更新概率
    NODE_REWARD_THRESHOLD = 0.045    # 节点奖励阈值，第二轮及以后使用
    NEW_FIND_RATE = 0.025
    PRE_SCAN_COUNT = {
        1: 3,    # 1星节点预探测个数
        2: 50,   # 2星节点预探测个数
        3: 200,   # 3星节点预探测个数
        4: 400,  # 4星节点预探测个数
        5: 500   # 5星节点预探测个数
    }
    TOP_NODES_BY_STAR = {
    1: 0,  # 选取100个1星节点
    2: 0,  # 选取200个2星节点
    3: 200,  # 选取300个3星节点
    4: 200,  # 选取200个4星节点
    5: 0   # 选取100个5星节点
}
    num_top1=0
    num_top1+=int(PRE_SCAN_COUNT[3])+int(PRE_SCAN_COUNT[4])
    epoch_1_num=max(1,int((buget_per_bgp0)*epoch_1_percent/num_top1))
    TOP_NODES_BY_STAR[3]=epoch_1_num
    TOP_NODES_BY_STAR[4]=epoch_1_num
    print(TOP_NODES_BY_STAR)

    MAX_THREAD_WORKERS = 32          # 多线程生成地址时的最大线程数
    MAX_PRE_SCAN_ADDRESSES = 1000000  # 每轮预探测最大地址数

    # 图结构的文件路径
    file_path = './graph_enhanced.pkl'
    
    # 读取BGP前缀列表
    with open('./val.txt', 'r') as f:
        bgps = [line.strip() for line in f]
    bgps=sorted(bgps)
    # 在BGP循环前加载图结构
    print("正在加载图结构..")
    one_star_nodes, two_star_nodes, three_star_nodes, four_star_nodes, five_star_nodes = read_graph(file_path)
    
    if one_star_nodes is None:
        print("加载图结构失败，程序退出")
        return
        
    # 排序节点
    one_star_nodes = sort_three_star_nodes_by_R(one_star_nodes)
    two_star_nodes = sort_three_star_nodes_by_R(two_star_nodes)
    three_star_nodes = sort_three_star_nodes_by_R(three_star_nodes)
    four_star_nodes = sort_three_star_nodes_by_R(four_star_nodes)
    five_star_nodes = sort_three_star_nodes_by_R(five_star_nodes)
    
    print(f"已加载所有节点")
    
    # 初始化奖励系统
    reward_system = NodeRewardSystem()
    reward_system.register_nodes_from_list(one_star_nodes, 1)
    reward_system.register_nodes_from_list(two_star_nodes, 2)
    reward_system.register_nodes_from_list(three_star_nodes, 3)
    reward_system.register_nodes_from_list(four_star_nodes, 4)
    reward_system.register_nodes_from_list(five_star_nodes, 5)
    
    # 创建所有节点的列表
    all_nodes = one_star_nodes + two_star_nodes + three_star_nodes + four_star_nodes + five_star_nodes
    print(f"总共有 {len(all_nodes)} 个节点")
    
    # 扫描参数
    all_budgets = 0
    all_hits = 0
    time1 = time.time()
    bgp_cnt = 0
    cover1 = 0
    all_limit = buget_per_bgp*len(bgps)

    # 开始扫描循环
    for bgp in bgps:
        # BGP开始
        PRE_SCAN_COUNT[3]=200
        PRE_SCAN_COUNT[4]=400
        print(f"\n\n========== 开始扫描 BGP: {bgp} ==========\n")
        hit_rates = None
        top_nodes = None
        budget_epoch=buget_per_bgp
        
        # 获取BGP前缀长度并设置奖励系统
        try:
            bgp_prefix_len = int(bgp.split('/')[1])
            reward_system.set_bgp_prefix_info(bgp_prefix_len)
        except:
            bgp_prefix_len = 32  # 默认值
            reward_system.set_bgp_prefix_info(bgp_prefix_len)
        
        # 首先重置所有节点的命中率、活跃地址列表和生成地址列表
        reset_all_nodes_reward(all_nodes)

        # 对节点进行并行去重，标记重复节点
        kept_nodes = deduplicate_nodes_for_bgp_parallel(bgp, all_nodes, max_workers=MAX_THREAD_WORKERS)
        print(f"BGP {bgp} 节点去重后保留了 {kept_nodes} 个唯一节点")
        
        # 对所有节点进行初始探测 - 使用优化的多线程初始探测
        hit_nodes, initial_active_ips, initial_scan_count = initial_probe_all_nodes(bgp, all_nodes)
        #hit_nodes, initial_active_ips, initial_scan_count=set(),[],0
        # 初始化BGP相关变量
        should_shutdown = False
        bgp_cnt += 1
        all_active = initial_active_ips.copy() if initial_active_ips else []
        budget = initial_scan_count
        all_budgets += initial_scan_count
        all_limit -= initial_scan_count
        budget_epoch-=initial_scan_count
        cover = len(all_active) > 0
        all_scanned = set(initial_active_ips) if initial_active_ips else set()
        # 对每个BGP进行多轮探测
        for round_num in range(MAX_ROUNDS_PER_BGP):
            print(f"\n=== BGP {bgp}, 第 {round_num+1}/{MAX_ROUNDS_PER_BGP} 轮 ===")
            
            # 监控当前内存状态
            monitor_memory_usage(f"Round {round_num+1} 开始")
            
            # 获取得分最高的N个节点
            if round_num == 0:
                # 第一轮：仅按得分选择顶级节点
                top_nodes = select_top_nodes_by_star_level(all_nodes, TOP_NODES_BY_STAR)
                node_selection_method = "按星级分别选择高分节点"
            else:
                # # 第二轮及以后：按得分选择且要求奖励值高于阈值
                # top_nodes = select_top_nodes_approx_extreme(
                #     all_nodes, TOP_NODES_COUNT, NODE_REWARD_THRESHOLD)
                # node_selection_method = f"按得分排序并且奖励值 > {NODE_REWARD_THRESHOLD}"

                top_nodes = select_top_nodes_with_heap(all_nodes, TOP_NODES_COUNT, NODE_REWARD_THRESHOLD)
                node_selection_method = "按得分排序"
                
            if not top_nodes:
                print("没有更多可探测的活跃节点")
                break
                
            print(f"选择了 {len(top_nodes)} 个顶级节点（{node_selection_method}）")
            
            # 收集所有待探测的节点
            nodes_to_scan = [(node, node.star_level) for node in top_nodes if not node.used]
            
            if not nodes_to_scan:
                print("没有可探测的非used节点")
                break
            
            print(f"收集了 {len(nodes_to_scan)} 个非used节点进行探测")
            
            # ========== 预探测阶段 ==========
            print("\n开始预探测阶段..")
            
            # 使用多线程并行生成预探测地址，同时记录生成的地址到各节点
            all_generated = parallel_efficient_pre_scan(
                bgp, nodes_to_scan, PRE_SCAN_COUNT, 
                random_ratio=RANDOM_RATIO, max_total=MAX_PRE_SCAN_ADDRESSES,
                max_workers=MAX_THREAD_WORKERS
            )

            print(f"所有节点共生成 {len(all_generated)} 个预探测组合")
            
            # 并行转换为标准IPv6格式
            convert_start = time.time()
            all_ips_to_scan = []
            
            def convert_batch(addr_batch):
                return [str2ipv6(addr) for addr, _ in addr_batch]
                
            batch_size = 2000000
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREAD_WORKERS) as executor:
                futures = []
                for i in range(0, len(all_generated), batch_size):
                    batch = all_generated[i:min(i+batch_size, len(all_generated))]
                    futures.append(executor.submit(convert_batch, batch))
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        batch_result = future.result()
                        all_ips_to_scan.extend(batch_result)
                    except Exception as e:
                        print(f"转换地址格式批次出错: {e}")
            
            log_time("预探测地址格式转换", convert_start)

            # 优化的扫描
            all_scanned=[standardize_ipv6_hex(addr, 32) for addr in all_scanned]
            all_scanned=set([f"{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}:{addr[20:24]}:{addr[24:28]}:{addr[28:32]}" for addr in all_scanned])
            print(f"扫描 {len(all_ips_to_scan)} 个IP地址..")
            scanned_ips, raw_ip_count = scan_addresses(bgp, all_ips_to_scan, all_scanned)

            # 清理不再需要的列表
            all_ips_to_scan = None

            # 更新预算和扫描记录
            budget += raw_ip_count
            all_budgets += raw_ip_count
            all_limit -= raw_ip_count
            budget_epoch-=raw_ip_count
            all_scanned.update(scanned_ips)
            
            if len(scanned_ips)>0.9*raw_ip_count:
                all_active.extend(scanned_ips)
                break
            # 更新活跃IP
            if scanned_ips:
                cover = True
                all_active.extend(scanned_ips)
                all_active = list(set(all_active))
                print(f"发现 {len(scanned_ips)} 个活跃IP，总计 {len(all_active)} 个活跃IP")
                
                # 将活跃地址转换为十六进制格式
                convert_start = time.time()
                # 使用标准化函数确保格式一致
                scanned_hex = convert(scanned_ips)
                log_time("活跃地址转换为十六进制", convert_start)
                
                # 提取节点列表并去重
                node_list = []
                seen_nodes = set()
                for _, node in all_generated:
                    if isinstance(node, TreeNode) and node not in seen_nodes:
                        node_list.append(node)
                        seen_nodes.add(node)
                
                # 使用直接归属方法计算命中情况 - 只是计算，不更新
                assigned_nodes = assign_addresses_direct(scanned_hex, node_list)
                
                # 计算命中率 - 基于生成地址和活跃地址比例
                hit_rates = calculate_node_hit_rates(assigned_nodes)
                
                # 按命中率选择节点进行全探
                qualified_nodes = []
                for node, star_level in nodes_to_scan:
                    if node.five == False: 
                        if node in hit_rates and hit_rates[node] > FULL_SCAN_THRESHOLD and hit_rates[node]<0.8:
                            qualified_nodes.append((node, star_level, hit_rates[node]))
                    else:
                        if node in hit_rates and hit_rates[node] > 2.5*FULL_SCAN_THRESHOLD and hit_rates[node]<0.8:
                            qualified_nodes.append((node, star_level, hit_rates[node]))
                
                print(f"预探测阶段检测到 {len(qualified_nodes)} 个合格节点")
                
                # 去重并按命中率排序选择要全探的节点
                unique_nodes_to_full_scan = {}
                for node, star_level, rate in qualified_nodes:
                    if node not in unique_nodes_to_full_scan or rate > unique_nodes_to_full_scan[node]:
                        unique_nodes_to_full_scan[node] = rate
                
                print(f"全探节点去重完成，选择 {len(unique_nodes_to_full_scan)} 个节点")
                if len(unique_nodes_to_full_scan)==0:
                    break
                
                # 清理不需要的数据释放内存
                node_list = None 
                seen_nodes = None
                qualified_nodes = None
                
                if unique_nodes_to_full_scan:
                    # 按命中率排序
                    sorted_nodes = sorted(unique_nodes_to_full_scan.items(), key=lambda x: x[1], reverse=True)

                    # 清理不再需要的字典
                    unique_nodes_to_full_scan = None

                    network, prefix_len = bgp.split('/')
                    prefix_len = int(prefix_len)
                    hex_length = math.ceil(prefix_len / 4)
                    hex_length = max(8, hex_length)

                    try:
                        bgp_ip = ipaddress.IPv6Address(network)
                        bgp_hex = bgp_ip.exploded.replace(':', '')
                    except:
                        bgp_hex = convert([network])[0]

                    bgp_prefix = bgp_hex[:hex_length]

                    unique_patterns = set()
                    selected_nodes = []
                    cnt_full=0
                    for node in sorted_nodes:
                        node1=node[0]
                        if hex_length > 8:
                            full_pattern = bgp_prefix + node1.pattern[hex_length-8:]
                        else:
                            full_pattern = bgp_prefix + node1.pattern

                        # Check if the full_pattern is unique
                        if full_pattern not in unique_patterns:
                            unique_patterns.add(full_pattern)
                            selected_nodes.append(node)
                            if full_pattern.count('*')==3 or full_pattern.count('*')==4 or full_pattern.count('*')==5:
                                cnt_full+=1

                        # Stop if we have selected enough nodes
                        if cnt_full >= MAX_FULL_SCAN_NODES:
                            break
                    #print(unique_patterns)

                    print(f"选择了 {len(selected_nodes)} 个节点进行全探(已去重)")

                    sorted_nodes=selected_nodes
                    # 使用多线程生成全探组合 - 同时记录生成的地址到节点
                    full_scan_generated = parallel_generate_addresses_full_scan(
                        bgp, sorted_nodes, max_workers=MAX_THREAD_WORKERS
                    )
                    
                    # 清理不再需要的列表
                    sorted_nodes = None
                    
                    # if full_scan_generated:
                    #     print(f"全探共生成 {len(full_scan_generated)} 个组合")
                        
                    #     # 转换为IPv6格式 - 使用多线程并行处理
                    #     convert_start = time.time()
                    #     full_scan_ips = []
                        
                    #     batch_size = 2000000
                    #     with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREAD_WORKERS) as executor:
                    #         futures = []
                    #         for i in range(0, len(full_scan_generated), batch_size):
                    #             end_idx = min(i+batch_size, len(full_scan_generated))
                    #             batch = full_scan_generated[i:end_idx]
                    #             futures.append(executor.submit(convert_batch, batch))
                            
                    #         for future in concurrent.futures.as_completed(futures):
                    #             try:
                    #                 batch_result = future.result()
                    #                 full_scan_ips.extend(batch_result)
                    #             except Exception as e:
                    #                 print(f"转换全探地址格式出错: {e}")
                        
                    #     log_time("全探地址转换", convert_start)

                    if len(full_scan_generated)!=0:
                        print(f"全探共生成 {len(full_scan_generated)} 个组合")
                        
                        # 转换为IPv6格式 - 先去重再并行处理
                        convert_start = time.time()
                        
                        # 1. 提取所有唯一的原始地址
                        unique_addrs = set()
                        for addr, _ in full_scan_generated:
                            unique_addrs.add(addr)
                        
                        print(f"地址去重: {len(full_scan_generated)}个原始地址 -> {len(unique_addrs)}个唯一地址")
                        
                        # 2. 转换唯一地址
                        unique_list = list(unique_addrs)
                        full_scan_ips = []  # 只存储转换后的唯一地址
                        
                        # 批量转换函数
                        def convert_unique_batch(start_idx, end_idx):
                            result = []
                            for addr in unique_list[start_idx:end_idx]:
                                # 高效地构建IPv6地址字符串
                                if len(addr) != 32:
                                    addr = standardize_ipv6_hex(addr, 32)
                                
                                # 使用内联分片构建IPv6地址
                                ipv6 = f"{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}:{addr[20:24]}:{addr[24:28]}:{addr[28:32]}"
                                result.append(ipv6)
                            return result
                        
                        # 并行处理唯一地址
                        batch_size = max(1, len(unique_list) // (MAX_THREAD_WORKERS * 2))
                        batch_size = min(batch_size, 100000)
                        
                        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREAD_WORKERS) as executor:
                            futures = []
                            for start_idx in range(0, len(unique_list), batch_size):
                                end_idx = min(start_idx + batch_size, len(unique_list))
                                futures.append(executor.submit(convert_unique_batch, start_idx, end_idx))
                            
                            # 收集结果
                            for future in concurrent.futures.as_completed(futures):
                                try:
                                    batch_result = future.result()
                                    full_scan_ips.extend(batch_result)
                                except Exception as e:
                                    print(f"转换唯一地址出错: {e}")
                        
                        log_time("全探地址转换", convert_start)
                        
                        # full_scan_ips = full_scan_generated
                        # 执行扫描
                        print(f"开始扫描 {len(full_scan_ips)} 个全探地址..")
                        
                        all_scanned=[standardize_ipv6_hex(addr, 32) for addr in all_scanned]
                        all_scanned=set([f"{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}:{addr[20:24]}:{addr[24:28]}:{addr[28:32]}" for addr in all_scanned])
                        full_scanned_ips, full_raw_ip_count = scan_addresses(bgp, full_scan_ips, all_scanned)
                        
                        # 清理不再需要的列表
                        full_scan_ips = None
                        
                        # 更新预算和扫描记录
                        budget += full_raw_ip_count
                        all_budgets += full_raw_ip_count
                        all_limit -= full_raw_ip_count
                        budget_epoch-=full_raw_ip_count
                        all_scanned.update(full_scanned_ips)
                        
                        # 更新活跃IP
                        if full_scanned_ips:
                            hit_before=len(all_active)
                            all_active.extend(full_scanned_ips)
                            all_active = list(set(all_active))
                            hit_after=len(all_active)
                            print(f"全探发现 {len(full_scanned_ips)} 个活跃IP，总计 {len(all_active)} 个活跃IP")
                            if hit_after-hit_before<NEW_FIND_RATE*full_raw_ip_count:
                                break
                            if hit_after-hit_before>0.9*full_raw_ip_count:
                                break
                            # 将活跃地址转换为十六进制格式 - 使用标准化函数
                            convert_start = time.time()
                            full_scanned_hex = convert(full_scanned_ips)
                            log_time("全探活跃地址转换", convert_start)
                            
                            # 提取参与全探的节点列表并去重
                            full_scan_nodes = []
                            seen_nodes = set()
                            for _, node in full_scan_generated:
                                if isinstance(node, TreeNode) and node not in seen_nodes:
                                    full_scan_nodes.append(node)
                                    seen_nodes.add(node)
                            
                            # 使用直接归属方法 - 已优化为多线程
                            full_assigned_nodes = assign_addresses_direct(full_scanned_hex, full_scan_nodes)
                            
                            # 计算命中率 - 基于生成地址和活跃地址比例 - 已优化为多线程
                            full_hit_rates = calculate_node_hit_rates(full_assigned_nodes)
                            
                            # 清理不再需要的列表
                            full_scan_generated = None
                            full_scanned_hex = None
                            full_scan_nodes = None
                            seen_nodes = None
                            
                            # 更新奖励 - 所有内部函数已优化为多线程
                            if full_assigned_nodes:
                                print(f"更新 {len(full_assigned_nodes)} 个全探节点奖励..")
                                updated_nodes = reward_system.batch_update_node_rewards(
                                    full_assigned_nodes, full_hit_rates, REWARD_SYSTEM_THRESHOLD)
                                print(f"全探更新了 {len(updated_nodes)} 个节点")
                            
                            # 清理不再需要的数据
                            full_hit_rates = None
                        else:
                            print("全探未发现活跃IP")
                else:
                    print("没有找到符合全探条件的节点")
            else:
                print("预探测未发现活跃IP，补充探测")
                # 清理内存
                all_generated = None
                temp=buget_per_bgp0
                temp=temp-initial_scan_count-raw_ip_count
                PRE_SCAN_COUNT[3]=0
                PRE_SCAN_COUNT[4]=500
                epoch_1_num=max(1,temp/1.2//500)
                TOP_NODES_BY_STAR[3]=0
                TOP_NODES_BY_STAR[4]=epoch_1_num
                top_nodes = select_top_nodes_by_star_level(all_nodes, TOP_NODES_BY_STAR)
                nodes_to_scan = [(node, node.star_level) for node in top_nodes if not node.used]
            
                if not nodes_to_scan:
                    print("没有可探测的非used节点")
                    break
                
                print(f"收集了 {len(nodes_to_scan)} 个非used节点进行探测")
                
                # ========== 预探测阶段 ==========
                print("\n开始补充预探测阶段..")
                
                # 使用多线程并行生成预探测地址，同时记录生成的地址到各节点
                all_generated = parallel_efficient_pre_scan(
                    bgp, nodes_to_scan, PRE_SCAN_COUNT, 
                    random_ratio=RANDOM_RATIO, max_total=MAX_PRE_SCAN_ADDRESSES,
                    max_workers=MAX_THREAD_WORKERS
                )

                print(f"所有节点共生成 {len(all_generated)} 个预探测组合")
                
                # 并行转换为标准IPv6格式
                convert_start = time.time()
                all_ips_to_scan = []
                
                def convert_batch(addr_batch):
                    return [str2ipv6(addr) for addr, _ in addr_batch]
                    
                batch_size = 2000000
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREAD_WORKERS) as executor:
                    futures = []
                    for i in range(0, len(all_generated), batch_size):
                        batch = all_generated[i:min(i+batch_size, len(all_generated))]
                        futures.append(executor.submit(convert_batch, batch))
                    
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            batch_result = future.result()
                            all_ips_to_scan.extend(batch_result)
                        except Exception as e:
                            print(f"转换地址格式批次出错: {e}")
                
                log_time("预探测地址格式转换", convert_start)

                # 优化的扫描
                all_scanned=[standardize_ipv6_hex(addr, 32) for addr in all_scanned]
                all_scanned=set([f"{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}:{addr[20:24]}:{addr[24:28]}:{addr[28:32]}" for addr in all_scanned])
                print(f"扫描 {len(all_ips_to_scan)} 个IP地址..")
                scanned_ips, raw_ip_count = scan_addresses(bgp, all_ips_to_scan, all_scanned)

                # 清理不再需要的列表
                all_ips_to_scan = None

                # 更新预算和扫描记录
                budget += raw_ip_count
                all_budgets += raw_ip_count
                all_limit -= raw_ip_count
                budget_epoch-=raw_ip_count
                all_scanned.update(scanned_ips)
                break
                

            # 检查预算限制
            if all_limit <= 0:
                print("已达到探测限制，停止")
                should_shutdown = True
                break
            if budget_epoch<=0:
                break

            # 清理内存
            hit_rates = None
            gc.collect()

            if should_shutdown:
                break
        
        # 更新统计信息
        if cover:
            cover1 += 1
        
        print('-----', bgp, '-----(', bgp_cnt, ')---', cover1)
        time2 = time.time()
        
        # 记录结果
        active_count = len(all_active) if all_active is not None else 0
        with open('./res30w.txt', 'a') as f:
            f.write(f'-----bgp:{bgp}-----budget:{budget}-----hitnum:{active_count}-----time:{time2-time1}\n')
        
        all_hits += active_count
        
        # 保存结果 - 使用缓冲写入
        bgp1 = bgp.replace('/', '_')
        if all_active:
            with open(f'./res0/{bgp1}.txt', 'w') as f:
                buffer = []
                for ip in all_active:
                    buffer.append(f"{ip}\n")
                if buffer:
                    f.writelines(buffer)
        
        print('------budgets:', all_budgets, '    hits:', all_hits, '    time:', time2-time1, '------')
        print(f"\n========== 完成扫描 BGP: {bgp} ==========\n")
        
        if(bgp_cnt%50==0):
            # BGP结束，执行内存清理 - 确保释放所有临时地址数据
            print("\n执行BGP间内存清理..")
            
            # 收集需要清理的临时数据
            round_data = {
                'all_active': all_active,
                'all_scanned': all_scanned, 
                'top_nodes': top_nodes
            }

            # 只有当hit_rates已定义时才添加到round_data
            if 'hit_rates' in locals() and hit_rates is not None:
                round_data['hit_rates'] = hit_rates
            
            # 执行彻底的内存清理
            cleanup_bgp_memory(all_nodes, round_data)
            
            # 显式重置关键变量
            all_active = None
            all_scanned = None
            hit_rates = None
            top_nodes = None

            # 在不再需要时
            all_ips_to_scan = None
            all_generated = None
            filtered_addresses = None
            # 强制垃圾回收
            gc.collect()
                
        # 记录当前内存状态
        current_memory = get_memory_usage()
        print(f"BGP {bgp} 处理完成后内存使用: {current_memory:.2f} MB")

        if should_shutdown:
            break
    
    # 程序结束
    program_end_time = time.time()
    program_end_memory = get_memory_usage()
    print(f"[程序结束] 总运行时间: {program_end_time - program_start_time:.2f} 秒")
    print(f"[程序结束] 最终内存使用: {program_end_memory:.2f} MB (净增加: {program_end_memory - program_start_memory:.2f} MB)")
    
    # 打印内存跟踪的Top 10快照
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')
    print("\n[内存分析] Top 10 内存使用位置:")
    for stat in top_stats[:10]:
        print(f"{stat.count} 块: {stat.size / 1024 / 1024:.1f} MB - {stat.traceback.format()[0]}")
    
    # 停止内存跟踪
    tracemalloc.stop()

if __name__ == "__main__":
    main()

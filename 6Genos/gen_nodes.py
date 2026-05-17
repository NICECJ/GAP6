import pickle
import tqdm
from collections import Counter, defaultdict

# 加载和处理各星级数据，这部分和原始代码保持一致
p1 = 0.75

# 加载1星节点数据
with open('../final_pattern/pattern_star1.pkl', 'rb') as file:
    data = pickle.load(file)
res = []
for key in data.keys():
    res += data[key]
# 创建一个 Counter 对象来统计字符串
string_counter = Counter()
for values in data.values():
    string_counter.update(values)
# 计算频率
cnt = 0
for key in string_counter.keys():
    cnt += string_counter[key]
for key in string_counter.keys():
    string_counter[key] = string_counter[key]/cnt
frequent1 = string_counter
# 计算条件概率
string_counter = Counter()
joint_counter = defaultdict(Counter)
for values in data.values():
    for i in range(len(values)):
        string_counter[values[i]] += 1
        for j in range(len(values)):
            if i != j:
                joint_counter[values[i]][values[j]] += 1
probabilities1 = {}
for string_a in string_counter:
    for string_b in joint_counter[string_a]:
        count_a = string_counter[string_a]
        count_a_and_b = joint_counter[string_a][string_b]
        
        if count_a > 0:
            probability = count_a_and_b / count_a
            if probability > p1:
                probabilities1[(string_a, string_b)] = probability
one_stars = list(set(res))

# 加载2星节点数据
with open('../final_pattern/pattern_star2.pkl', 'rb') as file:
    data = pickle.load(file)
res = []
for key in data.keys():
    res += data[key]
string_counter = Counter()
for values in data.values():
    string_counter.update(values)
cnt = 0
for key in string_counter.keys():
    cnt += string_counter[key]
for key in string_counter.keys():
    string_counter[key] = string_counter[key]/cnt
frequent2 = string_counter
string_counter = Counter()
joint_counter = defaultdict(Counter)
for values in data.values():
    for i in range(len(values)):
        string_counter[values[i]] += 1
        for j in range(len(values)):
            if i != j:
                joint_counter[values[i]][values[j]] += 1
probabilities2 = {}
for string_a in string_counter:
    for string_b in joint_counter[string_a]:
        count_a = string_counter[string_a]
        count_a_and_b = joint_counter[string_a][string_b]
        
        if count_a > 0:
            probability = count_a_and_b / count_a
            if probability > p1:
                probabilities2[(string_a, string_b)] = probability
two_stars = list(set(res))

# 加载3星节点数据
with open('../final_pattern/pattern_star3.pkl', 'rb') as file:
    data = pickle.load(file)
res = []
for key in data.keys():
    res += data[key]
string_counter = Counter()
for values in data.values():
    string_counter.update(values)
cnt = 0
for key in string_counter.keys():
    cnt += string_counter[key]
for key in string_counter.keys():
    string_counter[key] = string_counter[key]/cnt
frequent3 = string_counter
string_counter = Counter()
joint_counter = defaultdict(Counter)
for values in data.values():
    for i in range(len(values)):
        string_counter[values[i]] += 1
        for j in range(len(values)):
            if i != j:
                joint_counter[values[i]][values[j]] += 1
probabilities3 = {}
for string_a in string_counter:
    for string_b in joint_counter[string_a]:
        count_a = string_counter[string_a]
        count_a_and_b = joint_counter[string_a][string_b]
        
        if count_a > 0:
            probability = count_a_and_b / count_a
            if probability > p1:
                probabilities3[(string_a, string_b)] = probability
three_stars = list(set(res))

# 加载4星节点数据
with open('../final_pattern/pattern_star4.pkl', 'rb') as file:
    data = pickle.load(file)
res = []
for key in data.keys():
    res += data[key]
string_counter = Counter()
for values in data.values():
    string_counter.update(values)
cnt = 0
for key in string_counter.keys():
    cnt += string_counter[key]
for key in string_counter.keys():
    string_counter[key] = string_counter[key]/cnt
frequent4 = string_counter
string_counter = Counter()
joint_counter = defaultdict(Counter)
for values in data.values():
    for i in range(len(values)):
        string_counter[values[i]] += 1
        for j in range(len(values)):
            if i != j:
                joint_counter[values[i]][values[j]] += 1
probabilities4 = {}
for string_a in string_counter:
    for string_b in joint_counter[string_a]:
        count_a = string_counter[string_a]
        count_a_and_b = joint_counter[string_a][string_b]
        
        if count_a > 0:
            probability = count_a_and_b / count_a
            if probability > p1:
                probabilities4[(string_a, string_b)] = probability
four_stars = list(set(res))

# 加载5星节点数据
with open('../final_pattern/pattern_star5.pkl', 'rb') as file:
    data = pickle.load(file)
res = []
for key in data.keys():
    res += data[key]
string_counter = Counter()
for values in data.values():
    string_counter.update(values)
cnt = 0
for key in string_counter.keys():
    cnt += string_counter[key]
for key in string_counter.keys():
    string_counter[key] = string_counter[key]/cnt
frequent5 = string_counter
string_counter = Counter()
joint_counter = defaultdict(Counter)
for values in data.values():
    for i in range(len(values)):
        string_counter[values[i]] += 1
        for j in range(len(values)):
            if i != j:
                joint_counter[values[i]][values[j]] += 1
probabilities5 = {}
for string_a in string_counter:
    for string_b in joint_counter[string_a]:
        count_a = string_counter[string_a]
        count_a_and_b = joint_counter[string_a][string_b]
        
        if count_a > 0:
            probability = count_a_and_b / count_a
            if probability > p1:
                probabilities5[(string_a, string_b)] = probability
five_stars = list(set(res))

# 新的TreeNode类
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
        self.old_R = R
        self.brothers = []  # 兄弟节点列表（星数一样）
        self.star_level = star_level  # 星级 (1,2,3,4,5)
        self.parents = []  # 父节点列表（星数更高）
        self.used = False  # 是否已确定命中率(新的标记系统)
        self.update_count = 0  # 在一轮更新中的更新次数
        
        # 条件概率 - 假设已在导入节点时设置
        self.conditional_probs = {}  # 格式: {node: probability}
    
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
    
    def add_brother(self, brother):
        """添加兄弟节点（同星级）"""
        if brother not in self.brothers:
            self.brothers.append(brother)
    
    def is_child(self, node):
        # 原有逻辑，判断是否为子节点模式
        parent_pattern = self.pattern
        child_pattern = node.pattern
        if len(child_pattern) == len(parent_pattern):
            diff_count = 0
            match = True
            for i in range(len(parent_pattern)):
                if parent_pattern[i] != child_pattern[i]:
                    if parent_pattern[i].isdigit() and child_pattern[i] == '*':
                        diff_count += 1
                    else:
                        match = False
                        return False
            return match and diff_count == 1
        return False
    
    def __str__(self):
        return f"Node({self.star_level}★: {self.pattern}, R={self.R:.4f}, used={self.used})"

# 新的NodeFamily类
class NodeFamily:
    def __init__(self, one_star=None, two_star=None, three_star=None, four_star=None, five_star=None):
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
        self.family_id = None    # 家族ID，用于引用
    
    def is_complete(self):
        """检查家族是否包含所有星级节点"""
        return (self.one_star is not None and
                self.two_star is not None and 
                self.three_star is not None and 
                self.four_star is not None and 
                self.five_star is not None)
    
    def count_members(self):
        """计算家族中有效成员的数量"""
        count = 0
        if self.one_star is not None: count += 1
        if self.two_star is not None: count += 1
        if self.three_star is not None: count += 1
        if self.four_star is not None: count += 1
        if self.five_star is not None: count += 1
        return count
    
    def calculate_family_score(self):
        """基于家族中非used节点的属性计算整体得分 - 使用最高R值"""
        # 收集所有非null成员
        nodes = [node for node in [self.one_star, self.two_star, self.three_star, 
                                  self.four_star, self.five_star] if node is not None]
        
        if not nodes:
            return 0.0
        
        # 只考虑非used节点的R值
        max_r = 0.0
        for node in nodes:
            if not node.used and node.R > max_r:
                max_r = node.R
        
        self.family_score = max_r
        return max_r
    
    def get_node_by_level(self, level):
        """根据星级获取对应节点"""
        if level == 1: return self.one_star
        if level == 2: return self.two_star
        if level == 3: return self.three_star
        if level == 4: return self.four_star
        if level == 5: return self.five_star
        return None
    
    def set_node_by_level(self, level, node):
        """设置指定星级的节点"""
        if level == 1: self.one_star = node
        elif level == 2: self.two_star = node
        elif level == 3: self.three_star = node
        elif level == 4: self.four_star = node
        elif level == 5: self.five_star = node
    
    def __str__(self):
        """可读的家族表示"""
        return (f"Family #{self.family_id} - Score: {self.family_score:.4f} - Members: {self.count_members()}/5 "
                f"(1★: {self.one_star.pattern if self.one_star else 'None'}, "
                f"2★: {self.two_star.pattern if self.two_star else 'None'}, "
                f"3★: {self.three_star.pattern if self.three_star else 'None'}, "
                f"4★: {self.four_star.pattern if self.four_star else 'None'}, "
                f"5★: {self.five_star.pattern if self.five_star else 'None'})")

# 构建新的节点树
print("创建各星级节点...")
# 创建新节点，设置适当的star_level和R值
# one_star_nodes = [TreeNode(p, star_level=1, R=frequent1[p]) for p in one_stars]
# two_star_nodes = [TreeNode(p, star_level=2, R=frequent2[p]) for p in two_stars]
# three_star_nodes = [TreeNode(p, star_level=3, R=frequent3[p]) for p in three_stars]
# four_star_nodes = [TreeNode(p, star_level=4, R=frequent4[p]) for p in four_stars]
# five_star_nodes = [TreeNode(p, star_level=5, R=frequent5[p]) for p in five_stars]
one_star_nodes = [TreeNode(p, star_level=1, R=0) for p in one_stars]  # R=0
two_star_nodes = [TreeNode(p, star_level=2, R=0) for p in two_stars]  # R=0
three_star_nodes = [TreeNode(p, star_level=3, R=0) for p in three_stars]  # R=0
four_star_nodes = [TreeNode(p, star_level=4, R=0) for p in four_stars]  # R=0
five_star_nodes = [TreeNode(p, star_level=5, R=0) for p in five_stars]  # R=0

for n in one_star_nodes:
    n.R=frequent1[n.pattern]/10
for n in two_star_nodes:
    n.R=frequent2[n.pattern]/10
for n in three_star_nodes:
    n.R=frequent3[n.pattern]/10
for n in four_star_nodes:
    n.R=frequent4[n.pattern]/10
for n in five_star_nodes:
    n.R=frequent5[n.pattern]/10

# 创建节点映射表，方便通过pattern快速查找节点
node_map = {}
for nodes in [one_star_nodes, two_star_nodes, three_star_nodes, four_star_nodes, five_star_nodes]:
    for node in nodes:
        node_map[node.pattern] = node

# 设置node类型标志
for n in one_star_nodes:
    n.one = True
    n.starnum = 1
for n in two_star_nodes:
    n.two = True
    n.starnum = 2
for n in three_star_nodes:
    n.three = True
    n.starnum = 3
for n in four_star_nodes:
    n.four = True 
    n.starnum = 4
for n in five_star_nodes:
    n.five = True 
    n.starnum = 5

print("构建节点层次关系...")
# 构建星级层次关系（相差一个星的上下级关系）
print("1. 连接1星和2星节点...")
for n1 in tqdm.tqdm(one_star_nodes):
    for n2 in two_star_nodes:
        if n1.is_child(n2):  # 1星节点是2星节点的子节点
            n2.add_child(n1)  # 使用新的add_child方法建立双向连接

print("2. 连接2星和3星节点...")
for n1 in tqdm.tqdm(two_star_nodes):
    for n2 in three_star_nodes:
        if n1.is_child(n2):  # 2星节点是3星节点的子节点
            n2.add_child(n1)

print("3. 连接3星和4星节点...")
for n1 in tqdm.tqdm(three_star_nodes):
    for n2 in four_star_nodes:
        if n1.is_child(n2):  # 3星节点是4星节点的子节点
            n2.add_child(n1)

print("4. 连接4星和5星节点...")
for n1 in tqdm.tqdm(four_star_nodes):
    for n2 in five_star_nodes:
        if n1.is_child(n2):  # 4星节点是5星节点的子节点
            n2.add_child(n1)

print("构建同星级关系和条件概率...")
# 设置条件概率和兄弟关系 (同星级)
print("1. 处理1星节点的关系...")
for (string_a, string_b), prob in tqdm.tqdm(probabilities1.items()):
    n1 = node_map.get(string_a)
    n2 = node_map.get(string_b)
    if n1 and n2 and n1 != n2:
        n1.set_conditional_probability(n2, prob)
        n1.add_brother(n2)

print("2. 处理2星节点的关系...")
for (string_a, string_b), prob in tqdm.tqdm(probabilities2.items()):
    n1 = node_map.get(string_a)
    n2 = node_map.get(string_b)
    if n1 and n2 and n1 != n2:
        n1.set_conditional_probability(n2, prob)
        n1.add_brother(n2)

print("3. 处理3星节点的关系...")
for (string_a, string_b), prob in tqdm.tqdm(probabilities3.items()):
    n1 = node_map.get(string_a)
    n2 = node_map.get(string_b)
    if n1 and n2 and n1 != n2:
        n1.set_conditional_probability(n2, prob)
        n1.add_brother(n2)

print("4. 处理4星节点的关系...")
for (string_a, string_b), prob in tqdm.tqdm(probabilities4.items()):
    n1 = node_map.get(string_a)
    n2 = node_map.get(string_b)
    if n1 and n2 and n1 != n2:
        n1.set_conditional_probability(n2, prob)
        n1.add_brother(n2)

print("5. 处理5星节点的关系...")
for (string_a, string_b), prob in tqdm.tqdm(probabilities5.items()):
    n1 = node_map.get(string_a)
    n2 = node_map.get(string_b)
    if n1 and n2 and n1 != n2:
        n1.set_conditional_probability(n2, prob)
        n1.add_brother(n2)

# 构建家族结构
def build_families():
    """基于各星级节点构建家族结构"""
    print("构建节点家族...")
    families = []
    family_id = 1
    
    # 从1星节点开始，尝试构建家族
    for one_node in tqdm.tqdm(one_star_nodes):
        # 查找可能的2星级父节点
        for two_node in one_node.parents:
            # 查找可能的3星级父节点
            for three_node in two_node.parents:
                # 查找可能的4星级父节点
                for four_node in three_node.parents:
                    # 查找可能的5星级父节点
                    for five_node in four_node.parents:
                        # 创建一个完整的家族
                        family = NodeFamily(
                            one_star=one_node,
                            two_star=two_node,
                            three_star=three_node,
                            four_star=four_node,
                            five_star=five_node
                        )
                        family.family_id = family_id
                        family_id += 1
                        family.calculate_family_score()
                        families.append(family)
    
    # 如果完整家族较少，也考虑构建不完整的家族
    if len(families) < 1000:
        print("完整家族数量不足，构建不完整家族...")
        # 从2星节点开始构建
        for two_node in tqdm.tqdm(two_star_nodes):
            # 如果该2星节点已在完整家族中，跳过
            if any(f.two_star == two_node for f in families if f.is_complete()):
                continue
                
            for three_node in two_node.parents:
                for four_node in three_node.parents:
                    for five_node in four_node.parents:
                        family = NodeFamily(
                            two_star=two_node,
                            three_star=three_node,
                            four_star=four_node,
                            five_star=five_node
                        )
                        family.family_id = family_id
                        family_id += 1
                        family.calculate_family_score()
                        families.append(family)
        
        # 从3星节点开始构建
        for three_node in tqdm.tqdm(three_star_nodes):
            # 如果该3星节点已在较完整家族中，跳过
            if any(f.three_star == three_node for f in families if f.count_members() >= 4):
                continue
                
            for four_node in three_node.parents:
                for five_node in four_node.parents:
                    family = NodeFamily(
                        three_star=three_node,
                        four_star=four_node,
                        five_star=five_node
                    )
                    family.family_id = family_id
                    family_id += 1
                    family.calculate_family_score()
                    families.append(family)
    
    # 排序家族，优先完整家族，再按分数排序
    families.sort(key=lambda f: (-f.count_members(), -f.family_score))
    
    print(f"构建了 {len(families)} 个家族")
    print(f"完整家族数量: {sum(1 for f in families if f.is_complete())}")
    
    # 打印前10个家族信息
    print("\n前10个家族:")
    for i in range(min(10, len(families))):
        print(families[i])
    
    return families

# 构建家族
families = build_families()

# 保存家族和节点到pickle文件
graph = {
    'one_star_nodes': one_star_nodes,
    'two_star_nodes': two_star_nodes,
    'three_star_nodes': three_star_nodes,
    'four_star_nodes': four_star_nodes,
    'five_star_nodes': five_star_nodes,
    'families': families
}

# 为了保存和加载时避免循环引用问题，需要转换节点引用为模式字符串
def prepare_for_save(graph):
    """转换节点引用为模式字符串以准备保存"""
    for node_list_name in ['one_star_nodes', 'two_star_nodes', 'three_star_nodes', 'four_star_nodes', 'five_star_nodes']:
        for node in graph[node_list_name]:
            node.childs = [child.pattern for child in node.childs]
            node.parents = [parent.pattern for parent in node.parents]
            node.brothers = [brother.pattern for brother in node.brothers]
            
            # 转换条件概率字典的键
            new_cond_probs = {}
            for target_node, prob in node.conditional_probs.items():
                new_cond_probs[target_node.pattern] = prob
            node.conditional_probs = new_cond_probs
    
    # 转换家族中的节点引用
    for family in graph['families']:
        if family.one_star: family.one_star = family.one_star.pattern
        if family.two_star: family.two_star = family.two_star.pattern
        if family.three_star: family.three_star = family.three_star.pattern
        if family.four_star: family.four_star = family.four_star.pattern
        if family.five_star: family.five_star = family.five_star.pattern

prepare_for_save(graph)

# 保存到文件
print("保存图和家族结构...")
with open('../final_graph/graph_enhanced.pkl', 'wb') as file:
    pickle.dump(graph, file)

print('完成图和家族的构建和保存')
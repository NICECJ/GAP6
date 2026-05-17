import pickle
import ipaddress
import itertools
import subprocess
import math
import time
from collections import defaultdict

# =========================
# Probe backend config
# =========================
PROBE_BACKEND_DIR = "/home/chenjing/New-address-discovery"
PROBE_INPUT_FILE = os.path.join(PROBE_BACKEND_DIR, "input", "BGP_prefixes.txt")
PROBE_OUTPUT_FILE = os.path.join(PROBE_BACKEND_DIR, "output", "BGP.log")

# 默认协议，可改成 ack_rst / tcp_syn / icmpv6 ...
PROBE_PROTOCOL = "ack_rst"

# 是否打印探测后端输出
PROBE_VERBOSE = True

# 超时时间（秒）
PROBE_TIMEOUT = 600

class TreeNode:
    def __init__(self, pattern, parent=None):
        self.parent = parent
        self.pattern = pattern
        self.childs = []  # 是否存在边
        self.use = False
        self.SS = set()
        self.NDA = 0
        self.R = 0.0  # 节点先验概率
        self.one=False
        self.two=False
        self.three=False
        self.four=False
        self.five=False
        self.starnum=0

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

def read_graph(file_path):
    try:
        with open(file_path, 'rb') as file:
            graph = pickle.load(file)

        one_star_nodes = graph['one_star_nodes']
        two_star_nodes = graph['two_star_nodes']
        three_star_nodes = graph['three_star_nodes']
        four_star_nodes = graph['four_star_nodes']
        five_star_nodes = graph['five_star_nodes']

        # 将 childs 从模式列表恢复为节点对象列表
        all_nodes = one_star_nodes+two_star_nodes+three_star_nodes + four_star_nodes + five_star_nodes
        node_dict = {node.pattern: node for node in all_nodes}

        for nodes in [one_star_nodes,two_star_nodes,three_star_nodes, four_star_nodes, five_star_nodes]:
            for node in nodes:
                node.childs = [node_dict[pattern] for pattern in node.childs]

        print("图结构已成功读取")
        # 可以在这里对读取的图结构进行进一步操作
        print(f"One star nodes count: {len(one_star_nodes)}")
        print(f"Two star nodes count: {len(two_star_nodes)}")
        print(f"Three star nodes count: {len(three_star_nodes)}")
        print(f"Four star nodes count: {len(four_star_nodes)}")
        print(f"Five star nodes count: {len(five_star_nodes)}")

        return one_star_nodes,two_star_nodes,three_star_nodes, four_star_nodes, five_star_nodes
    except FileNotFoundError:
        print("未找到保存的图结构文件，请确保文件存在。")
        return None, None, None
    except Exception as e:
        print(f"读取图结构时出现错误: {e}")
        return None, None, None

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

def sort_three_star_nodes_by_R(three_star_nodes):
    if three_star_nodes:
        sorted_nodes = sorted(three_star_nodes, key=lambda node: node.R, reverse=True)
    return sorted_nodes

# 读取第一个图结构
file_path1 = "./graph_enhanced.pkl"
one_star_nodes1, two_star_nodes1,three_star_nodes1, four_star_nodes1, five_star_nodes1 = read_graph(file_path1)
one_star_nodes1, two_star_nodes1, three_star_nodes1, four_star_nodes1,five_star_nodes1 =sort_three_star_nodes_by_R(one_star_nodes1),sort_three_star_nodes_by_R(two_star_nodes1),sort_three_star_nodes_by_R(three_star_nodes1),sort_three_star_nodes_by_R(four_star_nodes1),sort_three_star_nodes_by_R(five_star_nodes1)
# 读取第二个图结构

# file_path2 = '../final_graph/graph_two.pkl'
# three_star_nodes2, four_star_nodes2, five_star_nodes2 = read_graph(file_path2)
# three_star_nodes2, four_star_nodes2, five_star_nodes2 =sort_three_star_nodes_by_R(three_star_nodes2),sort_three_star_nodes_by_R(four_star_nodes2),sort_three_star_nodes_by_R(five_star_nodes2)


with open('/home/zwj2/seedless_try/test_bgps.txt', 'r') as f:
    bgps = [line.strip() for line in f]

# 生成组合，返回紧凑格式
def generate_combinations(bgps, pattern_node):
    bgp,length=bgps.split('/')
    length=int(length)
    length=math.ceil(length/4)
    length=max(8,length)
    bgp=convert([bgp])[0][:length]
    full_pattern = bgp + pattern_node.pattern[length-8:]
    parts = full_pattern.split('*')
    star_count = len(parts) - 1
    if star_count == 0:
        yield full_pattern.ljust(32, '0')[:32]
        return
    hex_chars = '0123456789abcdef'
    for repl in itertools.product(hex_chars, repeat=star_count):
        combined = parts[0]
        for i in range(star_count):
            combined += repl[i] + parts[i + 1]
        combined = combined.ljust(32, '0')[:32]
        yield combined

def generate_combinations_p(bgps):
    bgp,length=bgps.split('/')
    length=int(length)
    length=math.ceil(length/4)
    length=max(8,length)
    bgp=convert([bgp])[0][:length]
    full_pattern = bgp + '****' + '0'*(27-length)+'1'
    parts = full_pattern.split('*')
    star_count = len(parts) - 1
    if star_count == 0:
        yield full_pattern.ljust(32, '0')[:32]
        return
    hex_chars = '0123456789abcdef'
    for repl in itertools.product(hex_chars, repeat=star_count):
        combined = parts[0]
        for i in range(star_count):
            combined += repl[i] + parts[i + 1]
        combined = combined.ljust(32, '0')[:32]
        yield combined

def str2ipv6(compact):
    return ':'.join([compact[i*4:(i+1)*4] for i in range(8)])

def run_smap(bgp):
    command = [
        'smap',
        '-m', 'f6',
        '-b', '100m',
        '-f', '../res1.txt',
        '--output_file_v6', f'../res1/{bgp}.txt',
        '--fields', 'source_addr'
    ]
    subprocess.run(command, check=True)
all_budgets=0
all_hits=0
import time
time1=time.time()
bgp_cnt=0
cover1=0
for bgp in bgps:
    bgp_cnt+=1
    print('-----',bgp,'-----(',bgp_cnt,')---',cover1)
    pts = one_star_nodes1[:3000]+two_star_nodes1[:300]+three_star_nodes1[:20]
    all_active=[]
    budget=0
    cnt=0
    cover=False
    epoches=0
    while pts:
        epoches+=1
        generated = []  # (compact_combo, node)
        buffer = []
        # 生成所有组合并写入文件
        with open('../res1.txt', 'w') as f:
            for node in pts:
                node.use=True
                for combo in generate_combinations(bgp, node):
                    standard_ip = str2ipv6(combo)
                    buffer.append(standard_ip + '\n')
                    generated.append( (combo, node) )
                    if len(buffer) >= 100000:
                        f.writelines(buffer)
                        buffer = []
            # if epoches==1:
            #     for combo in generate_combinations_p(bgp):
            #             standard_ip = str2ipv6(combo)
            #             buffer.append(standard_ip + '\n')
            #             if len(buffer) >= 10000:
            #                 f.writelines(buffer)
            #                 buffer = []
            if buffer:
                f.writelines(buffer)
    

        # 运行smap
        result_file = f'../res1.txt'
        raw_ips = set()
        with open(result_file, 'r') as f:
            for line in f:
                raw_ips.add(line.strip())  # 逐行添加到集合中去重
        with open(result_file, 'w') as f:
            for ip in raw_ips:
                f.write(f"{ip}\n")  # 逐行写入文件
        bgp1=bgp.replace('/','_')
        run_smap(bgp1)
        # 处理结果
        budget+=len(raw_ips)
        result_file = f'../res1/{bgp1}.txt'
        with open(result_file, 'r') as f:
            scanned_ips = [line.strip() for line in f]
        scanned_ips=scanned_ips[1:]
        if len(scanned_ips)!=0:
            cover=True
        hit1=list(set(all_active))
        all_active+=scanned_ips
        hit2=list(set(all_active))
        all_budgets+=len(raw_ips)
        if (len(hit2)-len(hit1))<=0.005*len(raw_ips):
            cnt+=1
        print('All hits:',len(hit2),'   Limited epoches:',cnt,'   budget:',budget)
        if cnt==2:
            break
        
        # 转换为紧凑格式集合
        scanned_set = set(convert(scanned_ips))
        # 统计命中
        node_hits = defaultdict(int)
        for combo, node in generated:
            if combo in scanned_set:
                node_hits[node] += 1
        # 确定下一层节点
        next_nodes = []
        next1=[]
        next2=[]
        next3=[]
        next4=[]
        next5=[]
        for node in pts:
            node.AAD = node_hits.get(node, 0)
            if node.AAD >= max(1,0.005*pow(node.starnum,16)):
            #if node.AAD!=0:
                if len(node.childs)!=0:
                    for c in node.childs:
                        if c.use == False:
                            c.use=True
                            if c.one==True:
                                next1.append(c)
                            if c.two==True:
                                next2.append(c)
                            if c.three==True:
                                next3.append(c)
                            if c.four==True:
                                next4.append(c)
                            if c.five==True:
                                next5.append(c)
        next1 = sorted(next1, key=lambda x: x.R, reverse=True) 
        next2 = sorted(next2, key=lambda x: x.R, reverse=True)
        next3 = sorted(next3, key=lambda x: x.R, reverse=True)      
        next4 = sorted(next4, key=lambda x: x.R, reverse=True)
        #next5 = sorted(next5, key=lambda x: x.R, reverse=True)[:1]
        next_nodes = next1 + next2+next3 + next4 + next5
        pts = next_nodes # 进入下一层
        print(f"Processed {len(generated)} combos, next nodes: {len(pts)}")
        
    if cover==True:
        cover1+=1
    all_hits+=len(hit2)
    with open(f'../res1/{bgp1}.txt', 'w') as f:
        for ip in list(set(all_active)):
            f.write(f"{ip}\n")  # 逐行写入文件
    time2=time.time()
    print('------budgets:',all_budgets,'    hits:',all_hits,'    time:',time2-time1,'------')

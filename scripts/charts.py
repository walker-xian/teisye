import os, argparse, logging, re
import numpy as np
import matplotlib.pyplot as plt 
import matplotlib.colors as mcolors

logger = logging.getLogger(__name__)

bar_colors = {'malloc':mcolors.CSS4_COLORS['orangered'],  'free':mcolors.CSS4_COLORS['lightcoral'], 
              'tsalloc':mcolors.CSS4_COLORS['royalblue'], 'tsfree':mcolors.CSS4_COLORS['cornflowerblue']}
    
report_perf = {
    'wc':{'malloc':{}, 'free':{}, 'tsalloc':{}, 'tsfree':{}}, 
    '512b':{'malloc':{}, 'free':{}, 'tsalloc':{}, 'tsfree':{}},
    '8kb':{'malloc':{}, 'free':{}, 'tsalloc':{}, 'tsfree':{}},
    '1mb':{'malloc':{}, 'free':{}, 'tsalloc':{}, 'tsfree':{}},
    }

report_mem = {'malloc':{}, 'tsalloc':{}}

def load_report(report_file):
    result_fields = {}
    with open(report_file, mode='r', encoding='UTF-8') as fd:
        for line in fd:
            parts = line.strip().split(':')
            if len(parts) > 1:
                result_fields[parts[0]] = parts[1].strip()
                if parts[0] == 'peak working set(KB)':
                    report_mem[result_fields['allocator']][int(result_fields['number of threads'])] =  int(result_fields[parts[0]])
            else:
                case,  allocate_time, _, free_time, *_ = re.split(r'\W+', line)
                if not case in ['CASE', 'huge']:
                    threads = int(result_fields['number of threads'])
                    if result_fields['allocator'] == 'malloc':
                        report_perf[case]['malloc'][threads] = int(allocate_time)
                        report_perf[case]['free'][threads] = int(free_time)
                    elif result_fields['allocator'] == 'tsalloc':
                        report_perf[case]['tsalloc'][threads] = int(allocate_time)
                        report_perf[case]['tsfree'][threads] = int(free_time)
                    else:
                        raise Exception()
                        
    logger.debug(f'{report_perf}')
    logger.debug(f'{report_mem}')
    
def perf_charts():
    def chart(case_name, case_data):
        values = {}
        for api_name in case_data:
            threads = sorted(case_data[api_name])
            values[api_name] = [case_data[api_name][x] for x in threads]
            
        bar_height = 0.15
        fig, ax = plt.subplots(figsize=(12, 6))
        y = np.arange(len(threads)) - bar_height * (len(case_data) - 1) / 2
        for i in values:
            logger.debug(f'{i}, {values[i]}, {y}')
            ax.barh(y, values[i], bar_height, label=i, color=bar_colors[i])
            y += bar_height

        ax.set_yticks(np.arange(len(threads)))
        ax.set_yticklabels(threads)
        ax.invert_yaxis()  # Labels read top-to-bottom
        ax.set_ylabel('Threads', fontweight ='bold', fontsize = 12)
        ax.set_xlabel('Time', fontweight ='bold', fontsize = 12)
        ax.set_title(f'{case}', fontweight ='bold', fontsize = 18)
        ax.legend()

        plt.tight_layout()
        plt.savefig(f'CASE_{case}.jpg')
        
    for case in report_perf:
        logger.debug(f'CSSE:{case}')
        chart(case, report_perf[case])
            
def mem_chart():
    values = {}
    for allocator in report_mem:
        threads = sorted(report_mem[allocator])
        values[allocator] = [report_mem[allocator][x] for x in threads]
        
    bar_height = 0.25
    fig, ax = plt.subplots(figsize=(12, 5))
    y = np.arange(len(threads)) - bar_height * (len(values) - 1) / 2
    for i in values:
        logger.debug(f'{i}, {values[i]}, {y}')
        ax.barh(y, values[i], bar_height, label=i, color=bar_colors[i])
        y += bar_height

    ax.set_yticks(np.arange(len(threads)))
    ax.set_yticklabels(threads)
    ax.invert_yaxis()  # Labels read top-to-bottom
    ax.set_ylabel('Threads', fontweight ='bold', fontsize = 12)
    ax.set_xlabel('Peak Working Set(KB)', fontweight ='bold', fontsize = 12)
    ax.set_title('Memory Usage', fontweight ='bold', fontsize = 18)
    ax.legend()

    plt.tight_layout()
    plt.savefig(f'memory_usage.jpg')

   
def main():
    parser = argparse.ArgumentParser(description='generate charts from HeapPerf report')
    parser.add_argument('report_file', help='HeapPerf report file')
    parser.add_argument('-l', '--log', metavar='level', default=logging.ERROR, type=int,
                    help='50-CRITICAL 40-ERROR(default) 30-WARNING 20-INFO 10-DEBUG')
    args = parser.parse_args()

    logger.addHandler(logging.StreamHandler())       
    logger.setLevel(args.log)
    logger.debug(args)
    
    load_report(args.report_file)
    perf_charts()
    mem_chart()
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(1)

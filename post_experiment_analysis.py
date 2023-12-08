import pandas as pd
import matplotlib.pyplot as plt
import sys
import numpy as np
from debug_colors import *

THEORETICAL = False

def get_sorted_key(line):
    numbers = line.split()
    first = -1
    second = -1
    try:
        first = numbers[0]
    except Exception as e:
        print(f"{RED}Couldn't read the first number!\nLine = {numbers}{RESET}")
    try:
        second = numbers[1]
        return (int(numbers[0]),int(numbers[1]))
    except Exception as e:
        print(f"{RED}Couldn't read the second number!\nLine = {numbers}{RESET}")
    exit()

def sort_file(data_file):
    with open(data_file,'r') as file:
        lines = file.readlines()
    # print(f"Lines befor:\n{lines}")
    lines = [ element for element in lines if element != '\n' ]
    # print(f"Lines after:\n{lines}")
    lines.sort(key=get_sorted_key)
    print(f"Sorted lines = {lines}")
    with open(data_file,'w') as file:
        file.writelines(lines)

def analysis_generate_graph(data_file,outfile,deterministic=False):
    # Initialize variables to store data
    line_data = {}  # Dictionary to store data for each line
    colors = plt.cm.viridis(range(0, 256, 256 // 10))  # Generate a set of distinct colors
    markers = ['o', 's', '^', 'D', 'v', 'p', '*', 'H', '<', '>']
    # Read data from the file
    with open(data_file, "r") as file:
        for line in file:
            if int(len(line.split())) < 3:
                continue
            try:
                line_number, x, y = map(float, line.split())
            except Exception as e:
                print(f"Line causing exception = {line}")
                continue
            if line_number not in line_data:
                line_data[line_number] = {"x": [], "y": []}
            line_data[line_number]["x"].append(x)
            line_data[line_number]["y"].append(y)
    # Create a plot with different colors for each line
    for line_number, data in line_data.items():
        int_line_num = int(line_number)
        plt.plot(data["x"], data["y"], label=f'Peer records = {int_line_num}', color=colors[int(line_number) % len(colors)], marker=markers[ int(line_number) % len(markers) ] )
    # Add labels, legend, and title
    plt.ylim(0, 1.10)
    xlim_max = 100 if (not deterministic) else 5
    plt.xlim(0,xlim_max)

    if not deterministic:
        plt.xlabel('Probability of Service (%)')
    else:
        plt.xlabel('Number of Alturistic Peers')

    plt.ylabel('Peer-Hit Ratio')
    plt.legend()

    title_prefix = "Actual data - " if (not THEORETICAL) else "Theoretical data - "
    if not deterministic:
        plt.title(title_prefix + 'Probabilistic Mode')
    else:
        plt.title(title_prefix + 'Deterministic Mode')

    plt.grid(True)
    ticks_interval = 10 if (not deterministic) else 1
    plt.xticks(np.arange(0, xlim_max+1, ticks_interval))
    plt.yticks(np.arange(0, 1.10, 0.10))
    plt.legend(loc='lower right')

    # Save the plot to a picture file (e.g., PNG)
    plt.savefig(outfile)
    # Display the plot (optional)
    plt.show()

def main():

    colorama_init()
    arglen = len(sys.argv)

    if( arglen < 3 ):
        print("{RED}Too few arguments{RESET}")
        return

    data_file = sys.argv[arglen-1]
    outfile = sys.argv[arglen-3]
    
    if "theoretical" in sys.argv:
        global THEORETICAL
        THEORETICAL = True

    if( sys.argv[arglen-2] == "ph_prob" ):
        print(f"{CYAN}Now generating the peer-hit-ratio VS serving probability graph{RESET}")
        sort_file(data_file)
        analysis_generate_graph(data_file,outfile)
        return
    elif ( sys.argv[arglen-2] == "ph_deter" ):
        print(f"{CYAN}Now generating the peer-hit-ratio VS alturistic peers graph{RESET}")
        sort_file(data_file)
        analysis_generate_graph(data_file,outfile,True)
        return

    print(f"{RED}Invalid graph type selected{RESET}")

if __name__ == "__main__":
    main()

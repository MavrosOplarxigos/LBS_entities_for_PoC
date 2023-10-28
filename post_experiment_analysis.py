import pandas as pd
import matplotlib.pyplot as plt
import sys
import numpy as np
from debug_colors import *

def get_sorted_key(line):
    numbers = line.split()
    return (int(numbers[0]),int(numbers[1]))

def sort_file(data_file):
    with open(data_file,'r') as file:
        lines = file.readlines()
    lines.sort(key=get_sorted_key)
    with open(data_file,'w') as file:
        file.writelines(lines)

def analysis_generate_graph(data_file,outfile):
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
    plt.xlim(0,100)
    plt.xlabel('Percent Probability of Service')
    plt.ylabel('Peer-Hit Ratio')
    plt.legend()
    plt.title('Actual data - Probabilistic Mode')

    plt.grid(True)
    plt.xticks(np.arange(0, 101, 10))
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
    
    if( sys.argv[arglen-2] == "ph" ):
        print(f"{CYAN}Now generating the peer-hit-ratio VS serving probability graph{RESET}")
        sort_file(data_file)
        analysis_generate_graph(data_file,outfile)
        return

    print(f"{RED}Invalid graph type selected{RESET}")

if __name__ == "__main__":
    main()

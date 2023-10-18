import matplotlib.pyplot as plt

# Initialize variables to store data
line_data = {}  # Dictionary to store data for each line
colors = plt.cm.viridis(range(0, 256, 256 // 10))  # Generate a set of distinct colors
markers = ['o', 's', '^', 'D', 'v', 'p', '*', 'H', '<', '>']

# Read data from the file
with open("mock_experiment_data.txt", "r") as file:
    for line in file:
        line_number, x, y = map(float, line.split())
        if line_number not in line_data:
            line_data[line_number] = {"x": [], "y": []}
        line_data[line_number]["x"].append(x)
        line_data[line_number]["y"].append(y)

# Create a plot with different colors for each line
for line_number, data in line_data.items():
    plt.plot(data["x"], data["y"], label=f'Line {line_number}', color=colors[int(line_number) % len(colors)], marker=markers[ int(line_number) % len(markers) ] )

# Add labels, legend, and title
plt.xlabel('X-axis')
plt.ylabel('Y-axis')
plt.legend()
plt.title('Data Points from File')

# Save the plot to a picture file (e.g., PNG)
plt.savefig('test_plot.png')

# Display the plot (optional)
plt.show()

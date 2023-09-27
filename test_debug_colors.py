from colorama import Fore

# Using dir() to list all attributes
color_attributes = [attr for attr in dir(Fore) if not callable(getattr(Fore, attr)) and not attr.startswith("__")]
print(color_attributes)

# Or simply print the attributes
# print(dir(Fore))

def add_numbers(a: float, b: float) -> float:
    """
    Adds two numbers together.

    Args:
        a (float): The first number to add
        b (float): The second number to add

    Returns:
        float: The sum of a and b

    Raises:
        TypeError: If either a or b are not numbers
    """
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        raise TypeError("Both inputs must be numbers")

    return a + b


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python add.py <number1> <number2>")
        sys.exit(1)

    try:
        num1 = float(sys.argv[1])
        num2 = float(sys.argv[2])
        result = add_numbers(num1, num2)
        print(f"{num1} + {num2} = {result}")
    except (TypeError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
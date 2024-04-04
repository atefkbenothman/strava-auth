from setuptools import setup


if __name__ == "__main__":
  with open("./README.md", "r") as f:
    long_description = f.read()

  setup(long_description=long_description, long_description_content_type="text/markdown")

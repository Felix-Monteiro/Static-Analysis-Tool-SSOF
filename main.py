import sys
import parser

def main(argv):
    parser.main(argv)
    pass


if __name__ == "__main__":
    if(len(sys.argv) == 3):
        main(sys.argv[1:])
    else:
        print("wrong number of args")
    pass
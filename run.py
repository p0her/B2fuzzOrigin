import subprocess

def main():
    while True:
        print('1. l2cap')
        print('2. rfcomm')
        layer = int(input('> '))
        if layer == 1:
            subprocess.run(['python3.8', 'l2cap/main.py'])
            break
        elif layer == 2:
            subprocess.run(['python3.8', 'rfcomm/main.py'])
            break
        else: 
            continue

if __name__ == '__main__':
    main()

from enum import Enum
from gpiozero import Button, LED
import sys, threading

# State  G B R
# Off    0 0 0
# Ready  1 0 0
# Sim1   1 1 0
# Sim2   1 0 1
# Sim3   1 1 1


class StateDefs(Enum):
    #   G B R
    OFF = (0, 0, 0)
    READY = (1, 0, 0)
    open_wifi = (1, 1, 0)
    wpa2_psk = (1, 0, 1)
    evil_twin = (1, 1, 1)


class RPIInterface:
    pressCallbacks: list[callable] = []

    def setLedState(self, state: StateDefs):
        self.green.value = state.value[0]
        self.blue.value = state.value[1]
        self.red.value = state.value[2]

    def onBtnPress(self):
        for callback in self.pressCallbacks:
            thread = threading.Thread(target=callback, daemon=True)
            thread.start()

    def __init__(self):
        self.state = StateDefs.OFF

        # Init GPIO
        self.button = Button(6, bounce_time=0.1)
        self.green = LED(10)
        self.blue = LED(11)
        self.red = LED(9)

        # Listeners
        self.button.when_pressed = self.onBtnPress

    def setState(self, newState: StateDefs):
        self.state = newState
        self.setLedState(newState)

    def getState(self):
        return self.state

    def registerPressListener(self, listener: callable):
        self.pressCallbacks.append(listener)


if __name__ == "__main__":
    rpiInterface = RPIInterface()

    try:

        def logPress():
            print("Button Pressed!")

        rpiInterface.registerPressListener(logPress)

        print("Started!")
        input("Press Enter to exit...\n")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

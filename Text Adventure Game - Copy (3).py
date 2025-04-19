# Text Adventure Game (expanded further)

import time
import random

class Game:
    def __init__(self):
        self.player = Player()
        self.world = World()
        self.is_running = True

    def start(self):
        print("Welcome to the Adventure Game!")
        self.world.intro()
        while self.is_running:
            self.loop()

    def loop(self):
        command = input("\n> ").strip().lower()
        if command in ["quit", "exit"]:
            self.is_running = False
            print("Thanks for playing!")
        elif command in ["look"]:
            self.world.describe_current_location()
        elif command.startswith("go "):
            direction = command[3:]
            self.world.move_player(direction)
        elif command == "inventory":
            self.player.show_inventory()
        elif command.startswith("take "):
            item = command[5:]
            self.world.take_item(item)
        elif command.startswith("use "):
            item = command[4:]
            self.player.use_item(item, self.world)
        elif command == "talk":
            self.world.talk_to_npc()
        else:
            print("Unknown command.")

class Player:
    def __init__(self):
        self.inventory = []
        self.health = 100
        self.gold = 0
        self.name = "Hero"

    def show_inventory(self):
        print(f"\n{self.name}'s Inventory:")
        if not self.inventory:
            print("You are carrying nothing.")
        else:
            for item in self.inventory:
                print(f" - {item}")
        print(f"Health: {self.health}")
        print(f"Gold: {self.gold}")

    def use_item(self, item, world):
        if item not in self.inventory:
            print("You don't have that item.")
            return
        if item == "key" and world.current_location == "castle gate":
            print("You unlock the castle gate!")
            world.unlock_castle()
        elif item == "potion":
            print("You drink the potion and restore health.")
            self.health = min(100, self.health + 25)
            self.inventory.remove("potion")
        else:
            print("You can't use that here.")

class World:
    def __init__(self):
        self.locations = {
            "forest": {
                "description": "You are in a dark forest.",
                "items": ["stick"],
                "npcs": ["old man"],
                "exits": {"north": "lake", "east": "castle gate"}
            },
            "lake": {
                "description": "A calm lake lies here.",
                "items": ["key"],
                "npcs": [],
                "exits": {"south": "forest"}
            },
            "castle gate": {
                "description": "A large gate blocks your path.",
                "items": [],
                "locked": True,
                "npcs": [],
                "exits": {"west": "forest", "north": "castle courtyard"}
            },
            "castle courtyard": {
                "description": "Inside the castle walls, peace reigns.",
                "items": ["potion"],
                "npcs": ["guard"],
                "exits": {"south": "castle gate"}
            }
        }
        self.current_location = "forest"
        self.npc_dialogue = {
            "old man": "Beware the shadows in the woods...",
            "guard": "Only those with the king's token may proceed."
        }

    def intro(self):
        print("You find yourself in a mysterious land. Where will you go?")
        self.describe_current_location()

    def describe_current_location(self):
        loc = self.locations[self.current_location]
        print(f"\n{loc['description']}")
        if loc.get("items"):
            print("You see:")
            for item in loc["items"]:
                print(f" - {item}")
        if loc.get("npcs"):
            print("You see people:")
            for npc in loc["npcs"]:
                print(f" - {npc}")
        print("Exits:")
        for direction in loc["exits"]:
            print(f" - {direction}")

    def move_player(self, direction):
        loc = self.locations[self.current_location]
        if direction in loc["exits"]:
            new_loc = loc["exits"][direction]
            if self.locations.get(new_loc, {}).get("locked", False):
                print("The way is locked.")
                return
            self.current_location = new_loc
            self.describe_current_location()
        else:
            print("You can't go that way.")

    def take_item(self, item):
        loc = self.locations[self.current_location]
        if item in loc.get("items", []):
            loc["items"].remove(item)
            game.player.inventory.append(item)
            print(f"You take the {item}.")
        else:
            print("That item is not here.")

    def unlock_castle(self):
        self.locations["castle gate"]["locked"] = False
        print("The gate creaks open...")

    def talk_to_npc(self):
        loc = self.locations[self.current_location]
        if not loc.get("npcs"):
            print("There is no one to talk to.")
            return
        print("Who do you want to talk to?")
        for i, npc in enumerate(loc["npcs"], 1):
            print(f"{i}. {npc}")
        choice = input("Enter number: ")
        if choice.isdigit() and 1 <= int(choice) <= len(loc["npcs"]):
            npc_name = loc["npcs"][int(choice)-1]
            dialogue = self.npc_dialogue.get(npc_name, "They have nothing to say.")
            print(f"{npc_name.capitalize()} says: \"{dialogue}\"")
        else:
            print("Invalid choice.")

if __name__ == '__main__':
    game = Game()
    game.start()

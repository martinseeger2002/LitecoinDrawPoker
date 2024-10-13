import os
import sys
import threading
from decimal import Decimal, ROUND_HALF_UP

import pygame
import pygame_gui
import json
from getCardCoords import get_card_coordinates
from dealCard import deal_card as original_deal_card
import pygame.mixer
from collections import deque
from pokerHandEvaluator import evaluate_hand
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from cashOut import send_litecoin
from buyIn import process_transaction

# Initialize Pygame
pygame.init()

# Initialize Pygame mixer
pygame.mixer.init()

# Load the shuffling sound
shuffling_sound = pygame.mixer.Sound("./data/shuffling-cards-4.mp3")

# Set up the display
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700
screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
pygame.display.set_caption("Five Card Draw Poker")

# Load the sprite sheet
sprite_sheet = pygame.image.load("./data/cardDeck.png").convert_alpha()

# Embed the JSON pay table
pay_table_json = '''
{
  "PayTable": {
    "RoyalFlush": [250, 500, 750, 1000, 4000],
    "StraightFlush": [50, 100, 150, 200, 250],
    "FourOfAKind": [25, 50, 75, 100, 125],
    "FullHouse": [8, 16, 24, 32, 40],
    "Flush": [5, 10, 15, 20, 25],
    "Straight": [4, 8, 12, 16, 20],
    "ThreeOfAKind": [3, 6, 9, 12, 15],
    "TwoPair": [2, 4, 6, 8, 10],
    "JacksOrBetter": [1, 2, 3, 4, 5]
  }
}
'''
pay_table = json.loads(pay_table_json)["PayTable"]

# Get the coordinates for the back of the card
back_coords = get_card_coordinates("Back")

# Define the size of each card in the sprite sheet
CARD_WIDTH = 148
CARD_HEIGHT = 230

# Scale factor for cards
SCALE_FACTOR = WINDOW_WIDTH / (8 * CARD_WIDTH)
SCALED_CARD_WIDTH = int(CARD_WIDTH * SCALE_FACTOR)
SCALED_CARD_HEIGHT = int(CARD_HEIGHT * SCALE_FACTOR)

# Create a surface for the card back
card_back = pygame.Surface((CARD_WIDTH, CARD_HEIGHT), pygame.SRCALPHA)
card_back.blit(sprite_sheet, (0, 0), (*back_coords, CARD_WIDTH, CARD_HEIGHT))

# Scale the card to fit the window (make it slightly smaller)
SCALED_CARD_WIDTH = int(WINDOW_WIDTH / 8)
SCALED_CARD_HEIGHT = int(SCALED_CARD_WIDTH * (CARD_HEIGHT / CARD_WIDTH))
scaled_card = pygame.transform.smoothscale(card_back, (SCALED_CARD_WIDTH, SCALED_CARD_HEIGHT))

# Global variables
credits = 0  # Starting credits
current_bet = 1
max_bet = 5
held_cards = [False] * 5
game_state = "NEW_GAME"  # Can be "NEW_GAME", "DEAL", or "DBL_UP"
current_win = 0
dbl_choice = None  # Store the player's double-up choice
drawn_card = None  # Initialize drawn_card to None
player_address = None
player_balance = None
buy_in_total = Decimal('0.0')  # Use Decimal for precise calculations
win_differential = Decimal('0.0')
player_pool_address = "<player pool address>"
player_pool_balance = Decimal('0.0')

# Define a refined color palette
COLORS = {
    'background': (15, 15, 35),  # Dark navy blue
    'text': (255, 255, 255),  # White
    'highlight': (191, 0, 255),  # Goldenrod
    'button': (70, 130, 180),  # Steel blue
    'button_text': (255, 255, 255),  # White
    'grid': (50, 50, 80),  # Muted blue-gray
    'table_bg': (25, 25, 50)  # Darker navy blue
}

# Add this variable to store the current hand
current_hand = [None] * 5

# Add these global variables
cards_drawn = ['Joker 1', 'Joker 2']
MAX_DRAW_ATTEMPTS = 100  # To prevent infinite loops

# Modify the deal_card function to use the cards_drawn list
def deal_card():
    global cards_drawn
    attempts = 0
    while attempts < MAX_DRAW_ATTEMPTS:
        card = original_deal_card()  # Rename the original deal_card function to original_deal_card
        if card not in cards_drawn:
            cards_drawn.append(card)
            return card
        attempts += 1
    raise RuntimeError("Unable to draw a unique card after multiple attempts")

# Modify the deal_initial_hand function
def deal_initial_hand():
    global credits, current_bet, game_state, cards_drawn
    if credits >= current_bet:
        credits -= current_bet
        shuffling_sound.play()
        cards_drawn.clear()
        cards_drawn.extend(['Joker 1', 'Joker 2'])  # Reset the drawn cards, keeping jokers out
        hand = [deal_card() for _ in range(5)]
        return hand
    else:
        return None

# Add a function to reset the game
def reset_game():
    global current_hand, held_cards, cards_drawn, drawn_card, dbl_choice
    current_hand = [None] * 5
    held_cards = [False] * 5
    drawn_card = None
    dbl_choice = None
    cards_drawn.clear()
    cards_drawn.extend(['Joker 1', 'Joker 2'])

# Modify the handle_game_buttons function
def handle_game_buttons(pos, main_button_rect, double_up_rect, dbl_draw_button_rect, take_win_rect):
    global game_state, held_cards, dbl_choice, credits, current_win, current_hand
    if main_button_rect.collidepoint(pos):
        if game_state in ["NEW_GAME", "DBL_UP"]:
            if credits == 0:
                display_message("Add Credits To Play")
            else:
                reset_game()
                current_hand = deal_initial_hand()
                if current_hand:
                    credits += current_win
                    game_state = "DEAL"
                    current_win = 0
                else:
                    print("Not enough credits!")
        elif game_state == "DEAL":
            # Replace held cards
            for i in range(5):
                if not held_cards[i]:
                    current_hand[i] = deal_card()
            # Evaluate the hand and update the win
            hand_ranking = evaluate_hand(current_hand)
            if hand_ranking in pay_table:
                current_win = pay_table[hand_ranking][current_bet - 1]
            else:
                current_win = 0
            game_state = "NEW_GAME"
    elif double_up_rect and double_up_rect.collidepoint(pos) and game_state == "NEW_GAME" and current_win > 0:
        game_state = "DBL_UP"
        reset_game()  # Reset variables specific to double up
    elif take_win_rect and take_win_rect.collidepoint(pos) and game_state == "NEW_GAME" and current_win > 0:
        credits += current_win
        current_win = 0

def get_current_hand_ranking():
    if game_state in ["NEW_GAME", "DEAL"] and all(current_hand):
        return evaluate_hand(current_hand)
    return None

def draw_pay_table(current_hand_ranking=None):
    font = pygame.font.SysFont('Arial', 22, bold=True)
    first_col_width = 180
    other_col_width = 90
    cell_height = 30
    table_width = first_col_width + 5 * other_col_width
    table_height = cell_height * (len(pay_table) + 1)
    start_x = (WINDOW_WIDTH - table_width) // 2
    start_y = 20

    # Draw background for the pay table
    pygame.draw.rect(screen, COLORS['table_bg'], (start_x, start_y, table_width, table_height))

    # Draw column headers
    headers = ["", "1 Coin", "2 Coins", "3 Coins", "4 Coins", "5 Coins"]
    for i, header in enumerate(headers):
        x = start_x + (first_col_width if i == 0 else first_col_width + (i - 1) * other_col_width)
        text = font.render(header, True, COLORS['highlight'])
        text_rect = text.get_rect(center=(x + (first_col_width if i == 0 else other_col_width) // 2, start_y + cell_height // 2))
        screen.blit(text, text_rect)

    # Draw pay table rows
    for i, (hand, payouts) in enumerate(pay_table.items()):
        y = start_y + (i + 1) * cell_height
        row_color = COLORS['highlight'] if hand == current_hand_ranking else COLORS['text']
        text = font.render(hand, True, row_color)
        text_rect = text.get_rect(midleft=(start_x + 5, y + cell_height // 2))
        screen.blit(text, text_rect)
        for j, payout in enumerate(payouts):
            x = start_x + first_col_width + j * other_col_width
            if j + 1 == current_bet:
                pygame.draw.rect(screen, COLORS['highlight'], (x, y, other_col_width, cell_height))
            text = font.render(str(payout), True, COLORS['table_bg'] if j + 1 == current_bet else row_color)
            text_rect = text.get_rect(center=(x + other_col_width // 2, y + cell_height // 2))
            screen.blit(text, text_rect)

    # Draw grid lines
    for i in range(len(pay_table) + 2):
        y = start_y + i * cell_height
        pygame.draw.line(screen, COLORS['grid'], (start_x, y), (start_x + table_width, y))
    pygame.draw.line(screen, COLORS['grid'], (start_x, start_y), (start_x, start_y + table_height))
    pygame.draw.line(screen, COLORS['grid'], (start_x + first_col_width, start_y), (start_x + first_col_width, start_y + table_height))
    for i in range(1, 6):
        x = start_x + first_col_width + i * other_col_width
        pygame.draw.line(screen, COLORS['grid'], (x, start_y), (x, start_y + table_height))

    return start_y + table_height

def draw_cards(cards, y_position):
    total_width = 5 * SCALED_CARD_WIDTH + 4 * 10  # 10px gap between cards
    start_x = (WINDOW_WIDTH - total_width) // 2
    y = y_position + 20  # 20px gap between pay table and cards

    card_positions = []
    for i, card in enumerate(cards):
        x = start_x + i * (SCALED_CARD_WIDTH + 10)
        if card:
            card_image = get_card_image(card)
        else:
            card_image = scaled_card  # This is the back of the card
        screen.blit(card_image, (x, y))
        card_positions.append(pygame.Rect(x, y, SCALED_CARD_WIDTH, SCALED_CARD_HEIGHT))

    # Print the cards in the hand and their rank
    if all(cards):
        hand_str = ", ".join(cards)
        rank = evaluate_hand(cards)
        print(f"Current hand: {hand_str}", file=sys.stderr)
        print(f"Hand rank: {rank}", file=sys.stderr)
        print("------------------------", file=sys.stderr)

    return card_positions

def draw_hold_buttons(card_positions):
    font = pygame.font.SysFont('Arial', 24, bold=True)
    button_width = SCALED_CARD_WIDTH
    button_height = 40
    button_y_offset = 10

    hold_buttons = []
    for i, card_rect in enumerate(card_positions):
        button_x = card_rect.x
        button_y = card_rect.y + SCALED_CARD_HEIGHT + button_y_offset
        button_rect = pygame.Rect(button_x, button_y, button_width, button_height)

        if held_cards[i]:
            pygame.draw.rect(screen, COLORS['highlight'], button_rect, border_radius=5)
            text = font.render("HELD", True, COLORS['table_bg'])
        else:
            if game_state == "DEAL":
                pygame.draw.rect(screen, COLORS['button'], button_rect, border_radius=5)
                text = font.render("HOLD", True, COLORS['button_text'])
            else:
                pygame.draw.rect(screen, COLORS['grid'], button_rect, border_radius=5)
                text = font.render("HOLD", True, COLORS['text'])

        text_rect = text.get_rect(center=button_rect.center)
        screen.blit(text, text_rect)
        hold_buttons.append(button_rect)

    return hold_buttons

def handle_hold_buttons(pos, hold_buttons, card_positions):
    global held_cards
    if game_state == "DEAL":
        for i, (button_rect, card_rect) in enumerate(zip(hold_buttons, card_positions)):
            if button_rect.collidepoint(pos) or card_rect.collidepoint(pos):
                held_cards[i] = not held_cards[i]
                break

def draw_credits():
    font = pygame.font.SysFont('Arial', 28, bold=True)
    credits_text = font.render(f"Credits: {credits}", True, COLORS['text'])
    credits_rect = credits_text.get_rect()
    credits_rect.bottomright = (WINDOW_WIDTH - 20, WINDOW_HEIGHT - 70)
    screen.blit(credits_text, credits_rect)

def draw_bet():
    font = pygame.font.SysFont('Arial', 28, bold=True)
    bet_text = font.render(f"Bet: {current_bet}", True, COLORS['text'])
    bet_rect = bet_text.get_rect()
    bet_rect.bottomleft = (20, WINDOW_HEIGHT - 70)
    screen.blit(bet_text, bet_rect)

def draw_win():
    font = pygame.font.SysFont('Arial', 28, bold=True)
    win_text = font.render(f"Win: {current_win}", True, COLORS['text'])
    win_rect = win_text.get_rect()
    win_rect.bottomleft = (150, WINDOW_HEIGHT - 70)  # Adjusted x-coordinate
    screen.blit(win_text, win_rect)

def draw_bet_buttons():
    font = pygame.font.SysFont('Arial', 24, bold=True)
    button_width = 30
    button_height = 30
    button_y = WINDOW_HEIGHT - 60

    minus_rect = pygame.Rect(20, button_y, button_width, button_height)
    plus_rect = pygame.Rect(60, button_y, button_width, button_height)

    if game_state != "DEAL":
        pygame.draw.rect(screen, COLORS['button'], minus_rect, border_radius=5)
        pygame.draw.rect(screen, COLORS['button'], plus_rect, border_radius=5)
        color = COLORS['button_text']
    else:
        pygame.draw.rect(screen, COLORS['grid'], minus_rect, border_radius=5)
        pygame.draw.rect(screen, COLORS['grid'], plus_rect, border_radius=5)
        color = COLORS['text']

    minus_text = font.render("-", True, color)
    plus_text = font.render("+", True, color)

    minus_text_rect = minus_text.get_rect(center=minus_rect.center)
    plus_text_rect = plus_text.get_rect(center=plus_rect.center)

    screen.blit(minus_text, minus_text_rect)
    screen.blit(plus_text, plus_text_rect)

    return minus_rect, plus_rect

def handle_bet_buttons(pos, minus_rect, plus_rect):
    global current_bet
    if game_state != "DEAL":
        if minus_rect.collidepoint(pos) and current_bet > 1:
            current_bet -= 1
        elif plus_rect.collidepoint(pos) and current_bet < max_bet:
            current_bet += 1

def draw_buy_cash_buttons():
    font = pygame.font.SysFont('Arial', 24, bold=True)
    button_width = 110
    button_height = 40
    button_y = WINDOW_HEIGHT - 60

    buy_in_rect = pygame.Rect(WINDOW_WIDTH - 240, button_y, button_width, button_height)
    cash_out_rect = pygame.Rect(WINDOW_WIDTH - 120, button_y, button_width, button_height)

    if game_state != "DEAL":
        pygame.draw.rect(screen, COLORS['button'], buy_in_rect, border_radius=5)
        pygame.draw.rect(screen, COLORS['button'], cash_out_rect, border_radius=5)
        color = COLORS['button_text']
    else:
        pygame.draw.rect(screen, COLORS['grid'], buy_in_rect, border_radius=5)
        pygame.draw.rect(screen, COLORS['grid'], cash_out_rect, border_radius=5)
        color = COLORS['text']

    buy_in_text = font.render("Buy In", True, color)
    cash_out_text = font.render("Cash Out", True, color)

    buy_in_text_rect = buy_in_text.get_rect(center=buy_in_rect.center)
    cash_out_text_rect = cash_out_text.get_rect(center=cash_out_rect.center)

    screen.blit(buy_in_text, buy_in_text_rect)
    screen.blit(cash_out_text, cash_out_text_rect)

    return buy_in_rect, cash_out_rect

def handle_buy_cash_buttons(pos, buy_in_rect, cash_out_rect):
    global credits, buy_in_total, player_address, player_balance, win_differential
    if game_state != "DEAL":
        if buy_in_rect.collidepoint(pos):
            buyin_ui()
        elif cash_out_rect.collidepoint(pos):
            if player_address is None:
                show_loading_screen("Load Wallet First")
            elif credits > 0:
                recipient_address = player_address
                # Convert credits back to Litecoin: 100 credits = 1 LTC
                amount_to_send = Decimal(credits) / Decimal('100')
                win_differential = amount_to_send - buy_in_total
                txid = cashOut_litecoin(recipient_address, amount_to_send, win_differential)
                if txid:
                    print(f"Cashout successful! TXID: {txid}")
                    print(f"Amount cashed out: {amount_to_send} LTC")
                    print(f"Total bought in: {buy_in_total} LTC")
                    print(f"Win Differential: {win_differential} LTC")
                    credits = 0
                    buy_in_total = Decimal('0.0')  # Reset buy_in_total after cashout
                    win_differential = Decimal('0.0')  # Reset win_differential after cashout
                else:
                    print("Cashout failed. Please try again.")
            else:
                print("No credits to cash out.")

def draw_game_buttons():
    font = pygame.font.SysFont('Arial', 24, bold=True)
    button_width = 150
    button_height = 40
    button_y = WINDOW_HEIGHT - 100
    gap = 20

    main_button_rect = pygame.Rect((WINDOW_WIDTH - button_width * 2 - gap) // 2, button_y, button_width, button_height)
    pygame.draw.rect(screen, COLORS['button'], main_button_rect, border_radius=5)

    if game_state == "DEAL":
        main_button_text = font.render("Deal", True, COLORS['button_text'])
    else:
        main_button_text = font.render("New Game", True, COLORS['button_text'])

    main_button_text_rect = main_button_text.get_rect(center=main_button_rect.center)
    screen.blit(main_button_text, main_button_text_rect)

    double_up_rect = None
    take_win_rect = None

    if game_state == "NEW_GAME" and current_win > 0:
        double_up_rect = pygame.Rect(main_button_rect.right + gap, button_y, button_width, button_height)
        pygame.draw.rect(screen, COLORS['button'], double_up_rect, border_radius=5)
        double_up_text = font.render("Double Up", True, COLORS['button_text'])
        double_up_text_rect = double_up_text.get_rect(center=double_up_rect.center)
        screen.blit(double_up_text, double_up_text_rect)

        # Adjust the "Take Win" button position
        take_win_y = button_y + button_height + (WINDOW_HEIGHT - button_y - 2 * button_height) // 2
        take_win_rect = pygame.Rect(double_up_rect.left, take_win_y, button_width, button_height)
        pygame.draw.rect(screen, COLORS['button'], take_win_rect, border_radius=5)
        take_win_text = font.render("Take Win", True, COLORS['button_text'])
        take_win_text_rect = take_win_text.get_rect(center=take_win_rect.center)
        screen.blit(take_win_text, take_win_text_rect)

    return main_button_rect, double_up_rect, take_win_rect

def get_ace_image(suit):
    full_suit_name = {'D': 'Diamonds', 'H': 'Hearts', 'C': 'Clubs', 'S': 'Spades'}[suit[0].upper()]
    coords = get_card_coordinates(f"Ace of {full_suit_name}")
    ace_surface = pygame.Surface((CARD_WIDTH, CARD_HEIGHT), pygame.SRCALPHA)
    ace_surface.blit(sprite_sheet, (0, 0), (*coords, CARD_WIDTH, CARD_HEIGHT))
    return pygame.transform.smoothscale(ace_surface, (SCALED_CARD_WIDTH, SCALED_CARD_HEIGHT))

def get_card_back_image():
    coords = get_card_coordinates("Back")
    back_surface = pygame.Surface((CARD_WIDTH, CARD_HEIGHT), pygame.SRCALPHA)
    back_surface.blit(sprite_sheet, (0, 0), (*coords, CARD_WIDTH, CARD_HEIGHT))
    return pygame.transform.smoothscale(back_surface, (SCALED_CARD_WIDTH, SCALED_CARD_HEIGHT))

def get_card_image(card):
    coords = get_card_coordinates(card)
    
    # Check if coordinates are valid
    if coords == (None, None):
        raise ValueError(f"Invalid card name: {card}")

    card_surface = pygame.Surface((CARD_WIDTH, CARD_HEIGHT), pygame.SRCALPHA)
    card_surface.blit(sprite_sheet, (0, 0), (*coords, CARD_WIDTH, CARD_HEIGHT))
    return pygame.transform.smoothscale(card_surface, (SCALED_CARD_WIDTH, SCALED_CARD_HEIGHT))

def draw_double_up_cards():
    card_width = SCALED_CARD_WIDTH
    card_height = SCALED_CARD_HEIGHT
    total_width = 4 * card_width + 3 * 20  # 20px gap between cards
    start_x = (WINDOW_WIDTH - total_width) // 2
    start_y = 50  # Start cards higher on the screen

    # Draw drawn_card (card back or drawn card) centered above the aces
    dbl_draw_card_x = WINDOW_WIDTH // 2 - card_width // 2
    dbl_draw_card_y = start_y
    if drawn_card:
        dbl_draw_card_image = get_card_image(drawn_card)  # Use the drawn card image
    else:
        dbl_draw_card_image = get_card_back_image()  # Use the card back image
    screen.blit(dbl_draw_card_image, (dbl_draw_card_x, dbl_draw_card_y))
    dbl_draw_card_pos = pygame.Rect(dbl_draw_card_x, dbl_draw_card_y, card_width, card_height)

    # Draw the four aces
    ace_positions = []
    for i, suit in enumerate(['D', 'H', 'C', 'S']):
        x = start_x + i * (card_width + 20)
        y = start_y + card_height + 40  # Position aces below the drawn card
        ace_image = get_ace_image(suit)
        screen.blit(ace_image, (x, y))
        ace_positions.append(pygame.Rect(x, y, card_width, card_height))

    # Draw credits, bet, and win
    draw_credits()
    draw_bet()
    draw_win()

    return dbl_draw_card_pos, ace_positions

def draw_double_up_buttons(screen, window_width, window_height, card_positions):
    global dbl_choice
    suit_buttons = []
    button_width = 100
    button_height = 50
    spacing = 20
    start_x = (window_width - (button_width * 4 + spacing * 3)) // 2

    # Position buttons below the cards
    start_y = card_positions[0].bottom + 20  # 20px gap between cards and buttons

    suits = ['♦', '♥', '♣', '♠']
    suit_names = ['diamonds', 'hearts', 'clubs', 'spades']

    for i, suit in enumerate(suits):
        x = start_x + i * (button_width + spacing)
        button_rect = pygame.Rect(x, start_y, button_width, button_height)
        suit_buttons.append(button_rect)

        button_color = COLORS['highlight'] if dbl_choice == suit_names[i] else COLORS['button']
        pygame.draw.rect(screen, button_color, button_rect, border_radius=5)

        font = pygame.font.SysFont('Arial', 24, bold=True)
        text_color = COLORS['table_bg'] if dbl_choice == suit_names[i] else COLORS['text']
        text = font.render(suit, True, text_color)
        text_rect = text.get_rect(center=button_rect.center)
        screen.blit(text, text_rect)

    red_button_rect = pygame.Rect(start_x, start_y + button_height + spacing, button_width * 2 + spacing, button_height)
    black_button_rect = pygame.Rect(start_x + button_width * 2 + spacing * 2, start_y + button_height + spacing, button_width * 2 + spacing, button_height)

    for button, color in [(red_button_rect, 'red'), (black_button_rect, 'black')]:
        button_color = COLORS['highlight'] if dbl_choice == color else COLORS['button']
        pygame.draw.rect(screen, button_color, button, border_radius=5)

        font = pygame.font.SysFont('Arial', 24, bold=True)
        text_color = COLORS['table_bg'] if dbl_choice == color else COLORS['text']
        text = font.render(color.upper(), True, text_color)
        text_rect = text.get_rect(center=button.center)
        screen.blit(text, text_rect)

    # Add "To Game" button
    to_game_rect = pygame.Rect(start_x, start_y + (button_height + spacing) * 2, button_width * 2 + spacing, button_height)
    pygame.draw.rect(screen, COLORS['button'], to_game_rect, border_radius=5)
    font = pygame.font.SysFont('Arial', 24, bold=True)
    text_surface = font.render("To Game", True, COLORS['text'])
    text_rect = text_surface.get_rect(center=to_game_rect.center)
    screen.blit(text_surface, text_rect)

    # Add "Draw" button
    action_rect = pygame.Rect(start_x + button_width * 2 + spacing * 2, start_y + (button_height + spacing) * 2, button_width * 2 + spacing, button_height)
    pygame.draw.rect(screen, COLORS['button'], action_rect, border_radius=5)
    text_surface = font.render("Draw", True, COLORS['text'])
    text_rect = text_surface.get_rect(center=action_rect.center)
    screen.blit(text_surface, text_rect)

    return suit_buttons, red_button_rect, black_button_rect, to_game_rect, action_rect

def perform_double_up():
    global current_win, credits, drawn_card, dbl_choice

    # Draw a card
    drawn_card = deal_card()

    # Redraw the screen to show the drawn card
    screen.fill(COLORS['background'])
    draw_game_elements()
    pygame.display.flip()
    pygame.time.wait(1000)  # Wait for 1 second to show the card

    # Determine if the player's choice was correct
    if dbl_choice in ['red', 'black']:
        # Red cards are hearts and diamonds
        card_suit = drawn_card.split(' of ')[1]
        card_color = 'red' if card_suit in ['Hearts', 'Diamonds'] else 'black'
        if dbl_choice == card_color:
            current_win *= 2
        else:
            current_win = 0
    else:
        # Suit match
        card_suit = drawn_card.split(' of ')[1].lower()
        if dbl_choice == card_suit.lower():
            current_win *= 4
        else:
            current_win = 0

    # Reset the choice after processing
    dbl_choice = None

def handle_double_up_choice(pos, card_positions, suit_buttons, red_button_rect, black_button_rect, to_game_rect, action_rect):
    global dbl_choice, game_state, current_win, drawn_card, credits

    # Handle suit buttons
    for i, (card_rect, button_rect) in enumerate(zip(card_positions, suit_buttons)):
        if card_rect.collidepoint(pos) or button_rect.collidepoint(pos):
            suits = ['diamonds', 'hearts', 'clubs', 'spades']
            dbl_choice = suits[i]
            return True  # Handled

    # Handle color buttons
    if red_button_rect.collidepoint(pos):
        dbl_choice = 'red'
        return True  # Handled
    elif black_button_rect.collidepoint(pos):
        dbl_choice = 'black'
        return True  # Handled

    # Handle "To Game" button
    elif to_game_rect.collidepoint(pos):
        credits += current_win
        current_win = 0
        game_state = "NEW_GAME"
        drawn_card = None
        dbl_choice = None
        return True  # Handled

    # Handle "Draw" button
    elif action_rect.collidepoint(pos):
        if dbl_choice is None:
            display_message("Please select a suit or color.")
            return True  # Handled
        else:
            perform_double_up()
            if current_win == 0:
                game_state = "NEW_GAME"
            return True  # Handled

    return False  # Not handled

def display_message(message):
    font = pygame.font.SysFont('Arial', 20, bold=True)
    text = font.render(message, True, COLORS['highlight'])
    text_rect = text.get_rect(center=(WINDOW_WIDTH // 2, WINDOW_HEIGHT // 2 - 20))
    screen.blit(text, text_rect)
    pygame.display.flip()
    pygame.time.wait(2000)  # Display the message for 2 seconds

def draw_player_pool_balance():
    balance_font = pygame.font.Font(None, 24)  # Smaller font size
    balance_text = f"Player Pool: {player_pool_balance} LTC"
    balance_surface = balance_font.render(balance_text, True, COLORS['text'])
    balance_rect = balance_surface.get_rect(midtop=(WINDOW_WIDTH // 2, 4))  # Move to the top
    screen.blit(balance_surface, balance_rect)

def draw_game_elements():
    global game_state, current_hand

    card_positions = []  # Initialize card_positions

    if game_state == "DBL_UP":
        # Draw only double up elements when in DBL_UP state
        dbl_draw_card_pos, card_positions = draw_double_up_cards()
        suit_buttons, red_button_rect, black_button_rect, to_game_rect, action_rect = draw_double_up_buttons(screen, WINDOW_WIDTH, WINDOW_HEIGHT, card_positions)

        return {
            'card_positions': card_positions,
            'suit_buttons': suit_buttons,
            'red_button_rect': red_button_rect,
            'black_button_rect': black_button_rect,
            'to_game_rect': to_game_rect,
            'action_rect': action_rect
        }
    else:
        # Draw the pay table
        current_hand_ranking = get_current_hand_ranking()
        pay_table_bottom = draw_pay_table(current_hand_ranking)

        # Draw cards
        card_positions = draw_cards(current_hand, pay_table_bottom)

        # Draw hold buttons
        hold_buttons = draw_hold_buttons(card_positions)

        # Draw credits, bet, and win
        draw_credits()
        draw_bet()
        draw_win()

        # Draw bet buttons
        minus_rect, plus_rect = draw_bet_buttons()

        # Draw buy in and cash out buttons
        buy_in_rect, cash_out_rect = draw_buy_cash_buttons()

        # Draw game buttons (New Game and Double Up or Draw)
        main_button_rect, double_up_rect, take_win_rect = draw_game_buttons()

        # Draw wallet button
        wallet_button_rect = draw_wallet_button()

        # Draw player pool balance
        draw_player_pool_balance()

        return {
            'card_positions': card_positions,  # Ensure this is always included
            'hold_buttons': hold_buttons,
            'minus_rect': minus_rect,
            'plus_rect': plus_rect,
            'buy_in_rect': buy_in_rect,
            'cash_out_rect': cash_out_rect,
            'main_button_rect': main_button_rect,
            'double_up_rect': double_up_rect,
            'take_win_rect': take_win_rect,
            'wallet_button_rect': wallet_button_rect
        }

def main_game_loop():
    running = True
    clock = pygame.time.Clock()

    # Display the message when the game starts
    display_message("Malfunctions Void All Payouts")

    while running:
        time_delta = clock.tick(60) / 1000.0
        screen.fill(COLORS['background'])
        ui_elements = draw_game_elements()

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.MOUSEBUTTONDOWN:
                pos = pygame.mouse.get_pos()
                if game_state == "DBL_UP":
                    handled = handle_double_up_choice(
                        pos,
                        ui_elements['card_positions'],
                        ui_elements['suit_buttons'],
                        ui_elements['red_button_rect'],
                        ui_elements['black_button_rect'],
                        ui_elements['to_game_rect'],
                        ui_elements['action_rect']
                    )
                else:
                    handle_hold_buttons(
                        pos,
                        ui_elements['hold_buttons'],
                        ui_elements['card_positions']  # Ensure this line is added
                    )
                    handle_bet_buttons(pos, ui_elements['minus_rect'], ui_elements['plus_rect'])
                    handle_buy_cash_buttons(pos, ui_elements['buy_in_rect'], ui_elements['cash_out_rect'])
                    handle_game_buttons(pos, ui_elements['main_button_rect'], ui_elements.get('double_up_rect'), None, ui_elements.get('take_win_rect'))
                    # Handle wallet button click
                    if ui_elements.get('wallet_button_rect') and ui_elements['wallet_button_rect'].collidepoint(pos):
                        display_message("Loading Wallets Please Wait...")
                        wallet_ui()

        pygame.display.flip()

# Additional functions from slot.py adapted for drawPoker.py

def draw_wallet_button():
    wallet_button_path = os.path.join("data", "wallet.png")
    if os.path.exists(wallet_button_path):
        wallet_button_image = pygame.image.load(wallet_button_path).convert_alpha()
        wallet_button_image = pygame.transform.smoothscale(wallet_button_image, (100, 40))
    else:
        wallet_button_image = None

    WALLET_BUTTON_X = WINDOW_WIDTH - 110
    WALLET_BUTTON_Y = 15 # Move to the top

    if wallet_button_image:
        screen.blit(wallet_button_image, (WALLET_BUTTON_X, WALLET_BUTTON_Y))
    else:
        # Draw a placeholder rectangle
        pygame.draw.rect(screen, COLORS['button'], (WALLET_BUTTON_X, WALLET_BUTTON_Y, 100, 40), border_radius=5)
        font = pygame.font.SysFont('Arial', 24, bold=True)
        text = font.render("Wallet", True, COLORS['button_text'])
        text_rect = text.get_rect(center=(WALLET_BUTTON_X + 50, WALLET_BUTTON_Y + 20))
        screen.blit(text, text_rect)

    return pygame.Rect(WALLET_BUTTON_X, WALLET_BUTTON_Y, 100, 40)

def load_rpc_credentials(filename):
    """Load RPC credentials from a configuration file."""
    credentials = {}
    with open(filename, 'r') as file:
        for line in file:
            if line.strip() and not line.strip().startswith('['):
                parts = line.strip().split('=')
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace('rpc', '')
                    credentials[key] = parts[1].strip()
    return credentials

def initialize_rpc_connection():
    # Determine the application's root directory
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        app_dir = os.path.dirname(sys.executable)
    else:
        # Running as script
        app_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the path to RPC.conf
    config_path = os.path.join(app_dir, 'RPC.conf')

    # Check if the file exists
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"RPC configuration file not found: {config_path}")

    try:
        credentials = load_rpc_credentials(config_path)
    except Exception as e:
        raise Exception(f"Failed to load RPC credentials: {str(e)}")

    rpc_user = credentials.get('user')
    rpc_password = credentials.get('password')
    rpc_host = credentials.get('host', 'localhost')
    rpc_port = credentials.get('port', '9332')  # Default Litecoin port

    if not all([rpc_user, rpc_password, rpc_host, rpc_port]):
        raise ValueError("Missing required RPC credentials in configuration file")

    rpc_url = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}"
    
    try:
        return AuthServiceProxy(rpc_url)
    except Exception as e:
        raise Exception(f"Failed to establish RPC connection: {str(e)}")

def get_player_addresses_and_balances():
    try:
        rpc_connection = initialize_rpc_connection()
        unspent_outputs = rpc_connection.listunspent()
        address_balances = {}
        for output in unspent_outputs:
            address = output['address']
            amount = output['amount']
            address_info = rpc_connection.validateaddress(address)
            if address_info.get('iswatchonly', False):
                continue
            if address not in address_balances:
                address_balances[address] = Decimal('0')
            address_balances[address] += Decimal(amount)
        addresses_and_balances = []
        for address, balance in address_balances.items():
            if balance > 0.001:
                addresses_and_balances.append((address, balance))
        return addresses_and_balances
    except JSONRPCException as e:
        print(f"JSONRPCException in get_player_addresses_and_balances: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in get_player_addresses_and_balances: {str(e)}")
        return []

def wallet_ui():
    global player_address, player_balance, player_pool_address
    manager = pygame_gui.UIManager((WINDOW_WIDTH, WINDOW_HEIGHT))

    try:
        addresses = get_player_addresses_and_balances()
        # Filter out the player_pool_address
        addresses = [(address, balance) for address, balance in addresses if address != player_pool_address]
        if not addresses:
            addresses = [('No Address', Decimal('0'))]
    except Exception as e:
        print(f"An error occurred while retrieving addresses: {str(e)}")
        addresses = [('No Address', Decimal('0'))]

    address_options = [(address, f"{address} ({balance:.8f} LTC)") for address, balance in addresses]

    dropdown = pygame_gui.elements.UIDropDownMenu(
        options_list=[option[1] for option in address_options],
        starting_option=address_options[0][1] if address_options else "No Address",
        relative_rect=pygame.Rect((WINDOW_WIDTH//2 - 200, WINDOW_HEIGHT//2 - 20), (400, 40)),
        manager=manager
    )

    submit_button = pygame_gui.elements.UIButton(
        relative_rect=pygame.Rect((WINDOW_WIDTH//2 - 50, WINDOW_HEIGHT//2 + 50), (100, 40)),
        text="Submit",
        manager=manager
    )

    running = True
    clock = pygame.time.Clock()
    while running:
        time_delta = clock.tick(60)/1000.0
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            manager.process_events(event)
            if event.type == pygame_gui.UI_BUTTON_PRESSED:
                if event.ui_element == submit_button:
                    selected_option = dropdown.selected_option
                    selected_address = selected_option.split()[0] if isinstance(selected_option, str) else selected_option[0].split()[0]
                    if selected_address != 'No Address':
                        player_address = selected_address
                        print(f"Selected address: {player_address}")
                        player_balance = next((Decimal(balance) for address, balance in addresses if address == player_address), None)
                    else:
                        print("No Address selected.")
                    running = False
        manager.update(time_delta)
        screen.fill(COLORS['background'])
        manager.draw_ui(screen)
        pygame.display.flip()

def buyin_ui():
    global credits, screen, player_pool_address, player_address, player_balance, buy_in_total
    if player_address is None or player_balance is None:
        print("No wallet selected. Please select a wallet first.")
        show_loading_screen("Load Wallet First")
        pygame.display.flip()
        return

    BUTTON_COLORS = COLORS['button']  # Use the button color from the COLORS dictionary
    font = pygame.font.SysFont('Arial', 24, bold=True)
    button_size = (80, 80)
    button_positions = [
        (50, 100), (150, 100), (250, 100),
        (50, 200), (150, 200), (250, 200),
        (50, 300), (150, 300), (250, 300),
        (50, 400), (150, 400)  # Add positions for '0' and '.'
    ]

    number_buttons = []
    for i in range(9):
        button = pygame.Surface(button_size, pygame.SRCALPHA)
        pygame.draw.rect(button, BUTTON_COLORS, button.get_rect(), border_radius=5)
        text = font.render(str(i + 1), True, COLORS['button_text'])
        text_rect = text.get_rect(center=(button_size[0] // 2, button_size[1] // 2))
        button.blit(text, text_rect)
        number_buttons.append((button, button_positions[i]))

    # Add '0' button
    zero_button = pygame.Surface(button_size, pygame.SRCALPHA)
    pygame.draw.rect(zero_button, BUTTON_COLORS, zero_button.get_rect(), border_radius=5)
    zero_text = font.render('0', True, COLORS['button_text'])
    zero_text_rect = zero_text.get_rect(center=(button_size[0] // 2, button_size[1] // 2))
    zero_button.blit(zero_text, zero_text_rect)

    # Add '.' button
    decimal_button = pygame.Surface(button_size, pygame.SRCALPHA)
    pygame.draw.rect(decimal_button, BUTTON_COLORS, decimal_button.get_rect(), border_radius=5)
    decimal_text = font.render('.', True, COLORS['button_text'])
    decimal_text_rect = decimal_text.get_rect(center=(button_size[0] // 2, button_size[1] // 2))
    decimal_button.blit(decimal_text, decimal_text_rect)

    submit_button = pygame.Surface((140, 50), pygame.SRCALPHA)
    cancel_button = pygame.Surface((140, 50), pygame.SRCALPHA)
    pygame.draw.rect(submit_button, COLORS['button'], submit_button.get_rect(), border_radius=5)
    pygame.draw.rect(cancel_button, COLORS['button'], cancel_button.get_rect(), border_radius=5)
    submit_text = font.render('Submit', True, COLORS['button_text'])
    cancel_text = font.render('Cancel', True, COLORS['button_text'])
    submit_button.blit(submit_text, submit_text.get_rect(center=(70, 25)))
    cancel_button.blit(cancel_text, cancel_text.get_rect(center=(70, 25)))

    running = True
    current_value = ''
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == pygame.MOUSEBUTTONDOWN:
                mouse_pos = pygame.mouse.get_pos()
                relative_pos = (mouse_pos[0] - (WINDOW_WIDTH - 500) // 2, mouse_pos[1] - (WINDOW_HEIGHT - 585) // 2)
                for i, (button, pos) in enumerate(number_buttons):
                    if pygame.Rect(pos, button_size).collidepoint(relative_pos):
                        current_value += str(i + 1)
                if pygame.Rect((150, 400), button_size).collidepoint(relative_pos):
                    current_value += '0'
                if pygame.Rect((250, 400), button_size).collidepoint(relative_pos):
                    if '.' not in current_value:
                        current_value += '.'
                if pygame.Rect((20, 500), (140, 50)).collidepoint(relative_pos):
                    if current_value:
                        try:
                            amount = Decimal(current_value)
                            if amount > player_balance:
                                print(f"Insufficient balance. Available: {player_balance} LTC")
                                error_text = font.render(f"Insufficient balance: {player_balance:.8f} LTC", True, (255, 0, 0))
                                error_rect = error_text.get_rect(center=(500 // 2, 585 - 50))
                                screen.blit(error_text, error_rect)
                                pygame.display.flip()
                                pygame.time.wait(3000)
                            else:
                                txid = buyIn_litecoin(player_address, amount)
                                if txid:
                                    # Convert amount to credits: 1 LTC = 100 credits
                                    credits += int(amount * Decimal('100'))
                                    player_balance -= amount
                                    buy_in_total += amount
                                    print(f"Bought in {amount} LTC! Transaction ID: {txid}")
                                    print(f"Total bought in: {buy_in_total} LTC")
                                    running = False
                                else:
                                    print("Transaction failed. No credits added.")
                        except Exception as e:
                            print(f"An error occurred: {str(e)}")
                            error_text = font.render(f"Error: {str(e)}", True, (255, 0, 0))
                            error_rect = error_text.get_rect(center=(500 // 2, 585 - 50))
                            screen.blit(error_text, error_rect)
                            pygame.display.flip()
                            pygame.time.wait(3000)
                if pygame.Rect((240, 500), (140, 50)).collidepoint(relative_pos):
                    running = False

        screen.fill(COLORS['background'])
        pygame.draw.rect(screen, COLORS['table_bg'], ((WINDOW_WIDTH - 500) // 2, (WINDOW_HEIGHT - 585) // 2, 500, 585))
        for button, pos in number_buttons:
            screen.blit(button, ((WINDOW_WIDTH - 500) // 2 + pos[0], (WINDOW_HEIGHT - 585) // 2 + pos[1]))
        screen.blit(zero_button, ((WINDOW_WIDTH - 500) // 2 + 150, (WINDOW_HEIGHT - 585) // 2 + 400))
        screen.blit(decimal_button, ((WINDOW_WIDTH - 500) // 2 + 250, (WINDOW_HEIGHT - 585) // 2 + 400))
        pygame.draw.rect(screen, COLORS['text'], ((WINDOW_WIDTH - 500) // 2 + 50, (WINDOW_HEIGHT - 585) // 2 + 30, 300, 50))
        display_text = font.render(current_value, True, COLORS['table_bg'])
        screen.blit(display_text, ((WINDOW_WIDTH - 500) // 2 + 60, (WINDOW_HEIGHT - 585) // 2 + 40))
        screen.blit(submit_button, ((WINDOW_WIDTH - 500) // 2 + 20, (WINDOW_HEIGHT - 585) // 2 + 500))
        screen.blit(cancel_button, ((WINDOW_WIDTH - 500) // 2 + 240, (WINDOW_HEIGHT - 585) // 2 + 500))
        balance_text = font.render(f"Balance: {player_balance:.8f} Lite", True, COLORS['text'])
        screen.blit(balance_text, ((WINDOW_WIDTH - 500) // 2 + 50, (WINDOW_HEIGHT - 585) // 2 + 550))
        pygame.display.flip()

    print(f"Current credits after buy-in: {credits}")

def show_loading_screen(text, duration=2000):
    overlay = pygame.Surface((WINDOW_WIDTH, WINDOW_HEIGHT), pygame.SRCALPHA)
    overlay.fill((0, 0, 0, 180))
    screen.blit(overlay, (0, 0))
    font = pygame.font.Font(None, 36)
    lines = text.split('\n')
    line_height = font.get_linesize()
    total_height = line_height * len(lines)
    y = (WINDOW_HEIGHT - total_height) // 2
    for line in lines:
        text_surface = font.render(line, True, COLORS['text'])
        text_rect = text_surface.get_rect(center=(WINDOW_WIDTH // 2, y))
        screen.blit(text_surface, text_rect)
        y += line_height
    pygame.display.flip()
    pygame.time.wait(duration)

def import_watch_only_address(rpc_connection, address):
    try:
        rpc_connection.importaddress(address, "player_pool", False)
        print(f"Successfully imported watch-only address: {address}")
    except JSONRPCException as e:
        print(f"Error importing watch-only address: {str(e)}")

def initialize_game():
    global player_pool_address
    try:
        rpc_connection = initialize_rpc_connection()
        import_watch_only_address(rpc_connection, player_pool_address)
        update_player_pool_balance()
    except Exception as e:
        print(f"Error initializing game: {str(e)}")

def update_player_pool_balance():
    global player_pool_balance
    try:
        rpc_connection = initialize_rpc_connection()
        unspent_outputs = rpc_connection.listunspent(0, 9999999, [player_pool_address])
        total_balance = sum((Decimal(output['amount']) for output in unspent_outputs), Decimal('0.0'))
        player_pool_balance = total_balance.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    except Exception as e:
        print(f"Error updating player pool balance: {str(e)}")

def buyIn_litecoin(address, amount):
    return process_transaction(address, amount)

def cashOut_litecoin(recipient_address, amount, win_differential):
    return send_litecoin(recipient_address, amount, win_differential)

# Ensure to call the main_game_loop() to start the game
if __name__ == "__main__":
    initialize_game()
    main_game_loop()

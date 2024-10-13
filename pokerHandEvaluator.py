from collections import Counter

def evaluate_hand(cards):
    # Handle Jokers
    jokers = [card for card in cards if 'Joker' in card]
    non_jokers = [card for card in cards if 'Joker' not in card]

    # Extract ranks and suits from non-joker cards
    ranks = [card.split(' of ')[0] for card in non_jokers]
    suits = [card.split(' of ')[1] for card in non_jokers]

    # Number of jokers
    num_jokers = len(jokers)

    # Check for flush
    is_flush = len(set(suits)) == 1 if suits else False

    # Get rank values
    rank_values = [rank_to_value(rank) for rank in ranks]

    # Check for straight
    is_straight = is_straight_with_jokers(rank_values, num_jokers)

    # Check for straight flush
    is_straight_flush = is_straight and is_flush

    # Count rank occurrences
    rank_counts = Counter(rank_values)

    # Get best hand considering rank counts and jokers
    best_hand = get_best_hand_with_jokers(rank_counts, num_jokers)

    # Determine final hand ranking
    if is_straight_flush:
        if set(rank_values) == {10, 11, 12, 13, 14} or num_jokers > 0:
            return "RoyalFlush"
        else:
            return "StraightFlush"
    elif best_hand == "Four of a Kind":
        return "FourOfAKind"
    elif best_hand == "Full House":
        return "FullHouse"
    elif is_flush:
        return "Flush"
    elif is_straight:
        return "Straight"
    else:
        return best_hand

def rank_to_value(rank):
    if rank.isdigit():
        return int(rank)
    elif rank == 'Jack':
        return 11
    elif rank == 'Queen':
        return 12
    elif rank == 'King':
        return 13
    elif rank == 'Ace':
        return 14
    else:
        raise ValueError(f"Unknown rank: {rank}")

def is_straight_with_jokers(values, num_jokers):
    unique_values = set(values)
    # For Ace-low straight
    if 14 in unique_values:
        unique_values.add(1)
    unique_values = sorted(unique_values)

    # Create a list of possible straights considering jokers
    for start in range(1, 11):
        straight = set(range(start, start + 5))
        missing_cards = len(straight - set(unique_values))  # Convert unique_values to a set here
        if missing_cards <= num_jokers:
            return True
    return False

def get_best_hand_with_jokers(rank_counts, num_jokers):
    counts = list(rank_counts.values())
    counts.sort(reverse=True)
    best_hand = "High Card"

    # Adjust counts with jokers
    adjusted_counts = counts[:]
    if adjusted_counts:
        adjusted_counts[0] += num_jokers
    else:
        adjusted_counts = [num_jokers]

    adjusted_counts.sort(reverse=True)

    # Determine best hand

    if adjusted_counts[0] == 4:
        return "FourOfAKind"
    elif adjusted_counts[0] == 3 and adjusted_counts[1] >= 2:
        return "FullHouse"
    elif adjusted_counts[0] == 3 and num_jokers >= 1:
        if len(adjusted_counts) > 1 and adjusted_counts[1] + num_jokers >= 2:
            return "FullHouse"
        else:
            return "ThreeOfAKind"
    elif adjusted_counts[0] == 3:
        return "ThreeOfAKind"
    elif adjusted_counts[0] == 2 and len(adjusted_counts) > 1 and adjusted_counts[1] >= 2:
        return "TwoPair"
    elif adjusted_counts[0] == 2 and num_jokers >= 1:
        return "ThreeOfAKind"
    elif adjusted_counts[0] == 2:
        # Check if the pair is Jacks or better
        pair_rank = max(rank for rank, count in rank_counts.items() if count == 2)
        if pair_rank >= 11:  # Jack's value is 11
            return "JacksOrBetter"
        else:
            return "OnePair"
    elif num_jokers >= 1:
        return "OnePair"
    else:
        return "HighCard"

import pygame
import sys
import random

# Initialize pygame
pygame.init()

# Set up fullscreen display
info = pygame.display.Info()
WIDTH, HEIGHT = info.current_w, info.current_h
win = pygame.display.set_mode((WIDTH, HEIGHT), pygame.FULLSCREEN)
pygame.display.set_caption('Snake Game Fullscreen')

# Colors
BLACK = (0, 0, 0)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
WHITE = (255, 255, 255)


# Snake settings
SNAKE_SIZE = 20

# Difficulty settings
DIFFICULTIES = {
    '1': ('Easy', 6),
    '2': ('Medium', 15),
    '3': ('Hard', 30)
}

def select_difficulty():
    selecting = True
    while selecting:
        win.fill((0, 0, 0))
        title = font.render('Select Difficulty', True, (255, 255, 255))
        win.blit(title, (WIDTH // 2 - title.get_width() // 2, HEIGHT // 4))
        for i, (key, (name, _)) in enumerate(DIFFICULTIES.items(), 1):
            txt = font.render(f'{key}: {name}', True, (255, 255, 255))
            win.blit(txt, (WIDTH // 2 - txt.get_width() // 2, HEIGHT // 2 + i * 60))
        pygame.display.update()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_1:
                    return DIFFICULTIES['1'][1]
                elif event.key == pygame.K_2:
                    return DIFFICULTIES['2'][1]
                elif event.key == pygame.K_3:
                    return DIFFICULTIES['3'][1]
                elif event.key == pygame.K_ESCAPE:
                    pygame.quit()
                    sys.exit()


# Font
font = pygame.font.SysFont('Arial', 48)


# Draw Pac-Man face at (x, y) with mouth open or closed and facing direction
def draw_pacman(x, y, body_size, mouth_open, direction):
    # Pac-Man color
    PACMAN_YELLOW = (255, 255, 0)
    PACMAN_EYE = (30, 30, 30)
    # Head size is 4x the body size
    size = body_size * 4
    # Set mouth angle
    if mouth_open:
        mouth_angle = 45
    else:
        mouth_angle = 10
    # Set direction angle (0=right, 90=down, 180=left, 270=up)
    if direction == 'RIGHT':
        base_angle = 0
    elif direction == 'DOWN':
        base_angle = 90
    elif direction == 'LEFT':
        base_angle = 180
    elif direction == 'UP':
        base_angle = 270
    else:
        base_angle = 0
    start_angle = base_angle + mouth_angle
    end_angle = base_angle - mouth_angle + 360
    import math
    center = (x + size // 2, y + size // 2)
    radius = size // 2
    mouth_rect = pygame.Rect(x, y, size, size)
    # Draw the main body as an arc (not a full circle)
    pygame.draw.arc(win, PACMAN_YELLOW, mouth_rect, math.radians(start_angle), math.radians(end_angle), size)
    # Fill the center to make it solid
    pygame.draw.circle(win, PACMAN_YELLOW, center, radius - size // 8)
    # Draw eye based on direction
    if direction == 'RIGHT':
        eye_x = x + size // 2 + size // 6
        eye_y = y + size // 2 - size // 4
    elif direction == 'LEFT':
        eye_x = x + size // 2 - size // 6
        eye_y = y + size // 2 - size // 4
    elif direction == 'UP':
        eye_x = x + size // 2
        eye_y = y + size // 2 - size // 3
    elif direction == 'DOWN':
        eye_x = x + size // 2
        eye_y = y + size // 2 + size // 6
    else:
        eye_x = x + size // 2 + size // 6
        eye_y = y + size // 2 - size // 4
    pygame.draw.circle(win, PACMAN_EYE, (eye_x, eye_y), size // 10)

def game_loop():

    SNAKE_SPEED = select_difficulty()
    game_over = False
    game_close = False

    # Determine food size based on difficulty
    food_size = SNAKE_SIZE
    if SNAKE_SPEED == DIFFICULTIES['1'][1]:  # Easy mode
        food_size = SNAKE_SIZE * 3

    x1 = WIDTH // 2
    y1 = HEIGHT // 2

    x1_change = 0
    y1_change = 0

    snake_List = []
    Length_of_snake = 1
    # Pac-Man direction and mouth state
    direction = 'RIGHT'
    mouth_open = True
    mouth_counter = 0

    foodx = round(random.randrange(0, WIDTH - food_size) / SNAKE_SIZE) * SNAKE_SIZE
    foody = round(random.randrange(0, HEIGHT - food_size) / SNAKE_SIZE) * SNAKE_SIZE

    clock = pygame.time.Clock()

    while not game_over:
        while game_close:
            win.fill(BLACK)
            msg = font.render('Game Over! Press Q-Quit or C-Play Again', True, RED)
            win.blit(msg, [WIDTH // 6, HEIGHT // 3])
            pygame.display.update()

            for event in pygame.event.get():
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_q:
                        game_over = True
                        game_close = False
                    if event.key == pygame.K_c:
                        game_loop()
                if event.type == pygame.QUIT:
                    game_over = True
                    game_close = False

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT and x1_change == 0:
                    x1_change = -SNAKE_SIZE
                    y1_change = 0
                elif event.key == pygame.K_RIGHT and x1_change == 0:
                    x1_change = SNAKE_SIZE
                    y1_change = 0
                elif event.key == pygame.K_UP and y1_change == 0:
                    y1_change = -SNAKE_SIZE
                    x1_change = 0
                elif event.key == pygame.K_DOWN and y1_change == 0:
                    y1_change = SNAKE_SIZE
                    x1_change = 0
                elif event.key == pygame.K_ESCAPE:
                    game_over = True

        # Border wrapping
        x1 += x1_change
        y1 += y1_change
        if x1 >= WIDTH:
            x1 = 0
        elif x1 < 0:
            x1 = WIDTH - SNAKE_SIZE
        if y1 >= HEIGHT:
            y1 = 0
        elif y1 < 0:
            y1 = HEIGHT - SNAKE_SIZE

        win.fill(BLACK)
        pygame.draw.rect(win, RED, [foodx, foody, food_size, food_size])
        snake_Head = [x1, y1]
        snake_List.append(snake_Head)
        if len(snake_List) > Length_of_snake:
            del snake_List[0]

        for segment in snake_List[:-1]:
            if segment == snake_Head:
                game_close = True

        # Animate Pac-Man mouth
        mouth_counter += 1
        if mouth_counter % 6 == 0:
            mouth_open = not mouth_open

        # Draw Pac-Man at head (face direction, 4x size)
        draw_pacman(x1 - (SNAKE_SIZE * 1.5), y1 - (SNAKE_SIZE * 1.5), SNAKE_SIZE, mouth_open, direction)

        # Draw the rest of the body as circles (yellow dots)
        for bx, by in snake_List[:-1]:
            pygame.draw.circle(win, (255, 255, 0), (bx + SNAKE_SIZE // 2, by + SNAKE_SIZE // 2), SNAKE_SIZE // 2)

        score = font.render(f'Score: {Length_of_snake - 1}', True, WHITE)
        win.blit(score, [10, 10])
        pygame.display.update()

        # Collision detection for food (account for larger food block)
        if (x1 < foodx + food_size and x1 + SNAKE_SIZE > foodx and
            y1 < foody + food_size and y1 + SNAKE_SIZE > foody):
            foodx = round(random.randrange(0, WIDTH - food_size) / SNAKE_SIZE) * SNAKE_SIZE
            foody = round(random.randrange(0, HEIGHT - food_size) / SNAKE_SIZE) * SNAKE_SIZE
            Length_of_snake += 1

        clock.tick(SNAKE_SPEED)

    pygame.quit()
    sys.exit()



    SNAKE_SPEED = select_difficulty()
    game_over = False
    game_close = False

    x1 = WIDTH // 2
    y1 = HEIGHT // 2

    x1_change = 0
    y1_change = 0

    snake_List = []
    Length_of_snake = 1

    foodx = round(random.randrange(0, WIDTH - SNAKE_SIZE) / SNAKE_SIZE) * SNAKE_SIZE
    foody = round(random.randrange(0, HEIGHT - SNAKE_SIZE) / SNAKE_SIZE) * SNAKE_SIZE

    clock = pygame.time.Clock()

    while not game_over:
        while game_close:
            win.fill(BLACK)
            msg = font.render('Game Over! Press Q-Quit or C-Play Again', True, RED)
            win.blit(msg, [WIDTH // 6, HEIGHT // 3])
            pygame.display.update()

            for event in pygame.event.get():
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_q:
                        game_over = True
                        game_close = False
                    if event.key == pygame.K_c:
                        game_loop()
                if event.type == pygame.QUIT:
                    game_over = True
                    game_close = False

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT and x1_change == 0:
                    x1_change = -SNAKE_SIZE
                    y1_change = 0
                elif event.key == pygame.K_RIGHT and x1_change == 0:
                    x1_change = SNAKE_SIZE
                    y1_change = 0
                elif event.key == pygame.K_UP and y1_change == 0:
                    y1_change = -SNAKE_SIZE
                    x1_change = 0
                elif event.key == pygame.K_DOWN and y1_change == 0:
                    y1_change = SNAKE_SIZE
                    x1_change = 0
                elif event.key == pygame.K_ESCAPE:
                    game_over = True

        # Border wrapping
        x1 += x1_change
        y1 += y1_change
        if x1 >= WIDTH:
            x1 = 0
        elif x1 < 0:
            x1 = WIDTH - SNAKE_SIZE
        if y1 >= HEIGHT:
            y1 = 0
        elif y1 < 0:
            y1 = HEIGHT - SNAKE_SIZE

        win.fill(BLACK)
        pygame.draw.rect(win, RED, [foodx, foody, SNAKE_SIZE, SNAKE_SIZE])
        snake_Head = [x1, y1]
        snake_List.append(snake_Head)
        if len(snake_List) > Length_of_snake:
            del snake_List[0]

        for segment in snake_List[:-1]:
            if segment == snake_Head:
                game_close = True

        draw_snake(snake_List)
        score = font.render(f'Score: {Length_of_snake - 1}', True, WHITE)
        win.blit(score, [10, 10])
        pygame.display.update()

        if x1 == foodx and y1 == foody:
            foodx = round(random.randrange(0, WIDTH - SNAKE_SIZE) / SNAKE_SIZE) * SNAKE_SIZE
            foody = round(random.randrange(0, HEIGHT - SNAKE_SIZE) / SNAKE_SIZE) * SNAKE_SIZE
            Length_of_snake += 1

        clock.tick(SNAKE_SPEED)

    pygame.quit()
    sys.exit()
if __name__ == '__main__':
    game_loop()

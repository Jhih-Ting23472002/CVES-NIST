import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-loading-overlay',
  standalone: true,
  imports: [
    CommonModule,
    MatProgressSpinnerModule,
    MatCardModule,
    MatIconModule
  ],
  template: `
    <div class="loading-overlay" *ngIf="show" [ngClass]="{'fullscreen': fullscreen}">
      <div class="loading-content">
        <mat-card class="loading-card">
          <mat-card-content>
            <div class="spinner-container">
              <mat-spinner 
                [diameter]="50" 
                strokeWidth="3"
                color="primary">
              </mat-spinner>
              <mat-icon class="loading-icon" *ngIf="icon">{{ icon }}</mat-icon>
            </div>
            
            <div class="loading-text">
              <h3 class="loading-title">{{ title }}</h3>
              <p class="loading-message" *ngIf="message">{{ message }}</p>
              <div class="loading-details" *ngIf="details">
                <small>{{ details }}</small>
              </div>
            </div>
            
            <!-- 進度條 (可選) -->
            <div class="progress-container" *ngIf="showProgress && progress >= 0">
              <div class="progress-bar">
                <div class="progress-fill" [style.width.%]="progress"></div>
              </div>
              <div class="progress-text">
                <span>{{ progress | number:'1.0-1' }}%</span>
                <span *ngIf="progressText">{{ progressText }}</span>
              </div>
            </div>
            
            <!-- 提示文字 -->
            <div class="loading-tips" *ngIf="tips && tips.length > 0">
              <div class="tip-item" *ngFor="let tip of tips">
                <mat-icon class="tip-icon">info</mat-icon>
                <span>{{ tip }}</span>
              </div>
            </div>
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [`
    .loading-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: rgba(0, 0, 0, 0.6);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 9999;
      backdrop-filter: blur(2px);
    }

    .loading-overlay.fullscreen {
      position: fixed;
      width: 100vw;
      height: 100vh;
    }

    .loading-content {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      height: 100%;
    }

    .loading-card {
      min-width: 320px;
      max-width: 480px;
      text-align: center;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      border-radius: 12px;
    }

    .spinner-container {
      position: relative;
      display: flex;
      justify-content: center;
      align-items: center;
      margin-bottom: 24px;
    }

    .loading-icon {
      position: absolute;
      font-size: 24px;
      color: #1976d2;
      z-index: 1;
    }

    .loading-text {
      margin-bottom: 16px;
    }

    .loading-title {
      margin: 0 0 8px 0;
      color: #1976d2;
      font-size: 1.4rem;
      font-weight: 500;
    }

    .loading-message {
      margin: 0 0 8px 0;
      color: #666;
      font-size: 1rem;
      line-height: 1.4;
    }

    .loading-details {
      color: #999;
      font-size: 0.85rem;
    }

    .progress-container {
      margin: 16px 0;
    }

    .progress-bar {
      width: 100%;
      height: 8px;
      background-color: #e0e0e0;
      border-radius: 4px;
      overflow: hidden;
      margin-bottom: 8px;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #1976d2, #42a5f5);
      border-radius: 4px;
      transition: width 0.3s ease;
    }

    .progress-text {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.85rem;
      color: #666;
    }

    .loading-tips {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid #e0e0e0;
    }

    .tip-item {
      display: flex;
      align-items: center;
      margin-bottom: 8px;
      font-size: 0.85rem;
      color: #666;
      text-align: left;
    }

    .tip-item:last-child {
      margin-bottom: 0;
    }

    .tip-icon {
      font-size: 16px;
      margin-right: 8px;
      color: #1976d2;
    }

    /* 動畫效果 */
    .loading-overlay {
      animation: fadeIn 0.3s ease-out;
    }

    .loading-card {
      animation: slideUp 0.4s ease-out;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
      }
      to {
        opacity: 1;
      }
    }

    @keyframes slideUp {
      from {
        transform: translateY(20px);
        opacity: 0;
      }
      to {
        transform: translateY(0);
        opacity: 1;
      }
    }

    /* 響應式設計 */
    @media (max-width: 480px) {
      .loading-card {
        min-width: 280px;
        margin: 16px;
      }
      
      .loading-title {
        font-size: 1.2rem;
      }
      
      .loading-message {
        font-size: 0.9rem;
      }
    }
  `]
})
export class LoadingOverlayComponent {
  @Input() show = false;
  @Input() title = '載入中...';
  @Input() message = '';
  @Input() details = '';
  @Input() icon = '';
  @Input() fullscreen = true;
  @Input() showProgress = false;
  @Input() progress = -1;
  @Input() progressText = '';
  @Input() tips: string[] = [];
}
load corr0.txt
figure(1)
subplot(2,2,1)
hold on
plot(corr0,'b')
plot(1:1000,corr0(:,1),'r')

load corr1.txt
subplot(2,2,2)
hold on
plot(corr1,'b')
plot(1:1000,corr1(:,2),'r')

load corr2.txt
subplot(2,2,3)
hold on
plot(corr2,'b')
plot(1:1000,corr2(:,3),'r')

load corr3.txt
subplot(2,2,4)
hold on
plot(corr3,'b')
plot(1:1000,corr3(:,4),'r')

